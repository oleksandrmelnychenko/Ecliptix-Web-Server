using System.Data.Common;
using System.Threading;
using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.CompiledQueries;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.QueryResults;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Utilities;
using Ecliptix.Protobuf.Membership;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Serilog;
using Membership = Ecliptix.Domain.Schema.Entities.MembershipEntity;

namespace Ecliptix.Domain.Memberships.Persistors;

public class VerificationFlowPersistorActor : PersistorBase<VerificationFlowFailure>
{
    private readonly IActorRef? _membershipPersistorActor;

    public VerificationFlowPersistorActor(
        IDbContextFactory<EcliptixSchemaContext> dbContextFactory,
        IActorRef? membershipPersistorActor = null)
        : base(dbContextFactory)
    {
        _membershipPersistorActor = membershipPersistorActor;
        Become(Ready);
    }

    public static Props Build(IDbContextFactory<EcliptixSchemaContext> dbContextFactory, IActorRef? membershipPersistorActor = null)
    {
        return Props.Create(() => new VerificationFlowPersistorActor(dbContextFactory, membershipPersistorActor));
    }

    private void Ready()
    {
        RegisterHandlers();
    }

    private void RegisterHandlers()
    {
        ReceivePersistorCommand<InitiateFlowAndReturnStateActorEvent, VerificationFlowQueryRecord>(
            InitiateFlowAsync,
            "InitiateVerificationFlow");

        ReceivePersistorCommand<RequestResendOtpActorEvent, string>(
            RequestResendOtpAsync,
            "RequestResendOtp");

        ReceivePersistorCommand<UpdateVerificationFlowStatusActorEvent, Unit>(
            UpdateVerificationFlowStatusAsync,
            "UpdateVerificationFlowStatus");

        ReceivePersistorCommand<EnsureMobileNumberActorEvent, Guid>(
            EnsureMobileNumberAsync,
            "EnsureMobileNumber");

        ReceivePersistorCommand<VerifyMobileForSecretKeyRecoveryActorEvent, Guid>(
            VerifyMobileForSecretKeyRecoveryAsync,
            "VerifyMobileForSecretKeyRecovery");

        ReceivePersistorCommand<GetMobileNumberActorEvent, MobileNumberQueryRecord>(
            GetMobileNumberAsync,
            "GetMobileNumber");

        ReceivePersistorCommand<CreateOtpActorEvent, CreateOtpResult>(
            CreateOtpAsync,
            "CreateOtp");

        ReceivePersistorCommand<UpdateOtpStatusActorEvent, Unit>(
            UpdateOtpStatusAsync,
            "UpdateOtpStatus");

        ReceivePersistorCommand<CheckMobileNumberAvailabilityActorEvent, string>(
            CheckMobileNumberAvailabilityAsync,
            "CheckMobileNumberAvailability");
    }

    private void ReceivePersistorCommand<TMessage, TResult>(
        Func<EcliptixSchemaContext, TMessage, CancellationToken, Task<Result<TResult, VerificationFlowFailure>>> handler,
        string operationName)
        where TMessage : class, ICancellableActorEvent
    {
        Receive<TMessage>(message =>
        {
            IActorRef replyTo = Sender;
            CancellationToken messageToken = message.CancellationToken;

            Task<Result<TResult, VerificationFlowFailure>> Operation(EcliptixSchemaContext ctx, CancellationToken ct)
            {
                CancellationToken effectiveToken = CombineCancellationTokens(ct, messageToken, out CancellationTokenSource? linkedSource);
                try
                {
                    return handler(ctx, message, effectiveToken);
                }
                finally
                {
                    linkedSource?.Dispose();
                }
            }

            ExecuteWithContext(Operation, operationName, messageToken).PipeTo(replyTo);
        });
    }

    private static CancellationToken CombineCancellationTokens(
        CancellationToken first,
        CancellationToken second,
        out CancellationTokenSource? linkedSource)
    {
        linkedSource = null;

        bool firstActive = first.CanBeCanceled;
        bool secondActive = second.CanBeCanceled;

        if (!firstActive && !secondActive)
            return CancellationToken.None;

        if (!firstActive)
            return second;

        if (!secondActive)
            return first;

        linkedSource = CancellationTokenSource.CreateLinkedTokenSource(first, second);
        return linkedSource.Token;
    }

    private static async Task<Result<VerificationFlowQueryRecord, VerificationFlowFailure>> InitiateFlowAsync(
        EcliptixSchemaContext ctx,
        InitiateFlowAndReturnStateActorEvent cmd,
        CancellationToken cancellationToken)
    {
        await using Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction =
            await ctx.Database.BeginTransactionAsync(cancellationToken);

        try
        {
            MobileNumberEntity? mobile = await MobileNumberQueries.GetByUniqueId(ctx, cmd.MobileNumberUniqueId, cancellationToken);
            if (mobile == null)
            {
                await transaction.RollbackAsync();
                return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("mobile_number_not_found"));
            }

            bool deviceExists = await DeviceQueries.ExistsByUniqueId(ctx, cmd.AppDeviceId, cancellationToken);
            if (!deviceExists)
            {
                await transaction.RollbackAsync();
                return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("device_not_found"));
            }

            VerificationFlowEntity? existingActiveFlow = await VerificationFlowQueries.GetActiveFlowForRecovery(
                ctx,
                cmd.MobileNumberUniqueId,
                cmd.AppDeviceId,
                ConvertPurposeToString(cmd.Purpose),
                cancellationToken);

            if (existingActiveFlow != null)
            {
                await ctx.VerificationFlows
                    .Where(vf => vf.Id == existingActiveFlow.Id)
                    .ExecuteUpdateAsync(setters => setters
                        .SetProperty(vf => vf.ConnectionId, (long?)cmd.ConnectId)
                        .SetProperty(vf => vf.UpdatedAt, DateTimeOffset.UtcNow),
                        cancellationToken);

                await ctx.OtpCodes
                    .Where(o => o.VerificationFlowId == existingActiveFlow.Id &&
                                o.Status == "active" &&
                                !o.IsDeleted)
                    .ExecuteUpdateAsync(setters => setters
                        .SetProperty(o => o.Status, "expired")
                        .SetProperty(o => o.UpdatedAt, DateTimeOffset.UtcNow),
                        cancellationToken);

                await transaction.CommitAsync(cancellationToken);

                existingActiveFlow.ConnectionId = cmd.ConnectId;
                existingActiveFlow.UpdatedAt = DateTimeOffset.UtcNow;
                existingActiveFlow.MobileNumber = mobile;
                existingActiveFlow.OtpCodes = new List<OtpCodeEntity>();

                return MapToVerificationFlowRecord(existingActiveFlow);
            }

            if (cmd.Purpose == VerificationPurpose.PasswordRecovery)
            {
                Log.Information("[INITIATE-PASSWORD-RECOVERY] Password recovery flow initiated for mobile ID {MobileId}", mobile.UniqueId);

                int recoveryCount = await VerificationFlowQueries.CountRecentPasswordRecovery(
                    ctx, mobile.UniqueId, DateTimeOffset.UtcNow.AddHours(-1), cancellationToken);

                Log.Information("[INITIATE-PASSWORD-RECOVERY] Recent password recovery count: {Count} for mobile ID {MobileId}", recoveryCount, mobile.UniqueId);

                if (recoveryCount >= 3)
                {
                    await transaction.RollbackAsync();
                    return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.RateLimitExceeded("password_recovery_rate_limit_exceeded"));
                }

                List<VerificationFlowEntity> oldActiveFlows = await ctx.VerificationFlows
                    .Where(vf => vf.MobileNumberId == mobile.UniqueId &&
                                 vf.Purpose == "password_recovery" &&
                                 (vf.Status == "pending" || vf.Status == "verified") &&
                                 !vf.IsDeleted)
                    .ToListAsync(cancellationToken);

                Log.Information("[INITIATE-PASSWORD-RECOVERY] Found {Count} old password recovery flows (pending + verified) to expire for mobile ID {MobileId}",
                    oldActiveFlows.Count, mobile.UniqueId);

                if (oldActiveFlows.Count > 0)
                {
                    foreach (VerificationFlowEntity oldFlow in oldActiveFlows)
                    {
                        string oldStatus = oldFlow.Status;
                        oldFlow.Status = "expired";
                        oldFlow.UpdatedAt = DateTimeOffset.UtcNow;
                        Log.Information("[INITIATE-PASSWORD-RECOVERY] Expiring flow {FlowId} with status '{OldStatus}' for mobile ID {MobileId}",
                            oldFlow.UniqueId, oldStatus, mobile.UniqueId);
                    }

                    Log.Information("[INITIATE-PASSWORD-RECOVERY] Successfully expired {Count} old password recovery flows", oldActiveFlows.Count);
                }
            }

            int mobileFlowCount = await VerificationFlowQueries.CountRecentByMobileId(
                ctx, mobile.UniqueId, DateTimeOffset.UtcNow.AddHours(-1), cancellationToken);
            if (mobileFlowCount >= 30)
            {
                await transaction.RollbackAsync();
                return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.RateLimitExceeded("rate_limit_exceeded"));
            }

            int deviceFlowCount = await VerificationFlowQueries.CountRecentByDevice(
                ctx, cmd.AppDeviceId, DateTimeOffset.UtcNow.AddHours(-1), cancellationToken);
            if (deviceFlowCount >= 10)
            {
                await transaction.RollbackAsync();
                return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.RateLimitExceeded("device_rate_limit_exceeded"));
            }

            VerificationFlowEntity flow = new()
            {
                UniqueId = Guid.NewGuid(),
                MobileNumberId = mobile.UniqueId,
                AppDeviceId = cmd.AppDeviceId,
                Purpose = ConvertPurposeToString(cmd.Purpose),
                Status = "pending",
                ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(15),
                ConnectionId = cmd.ConnectId,
                OtpCount = 0,
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow,
                IsDeleted = false
            };

            ctx.VerificationFlows.Add(flow);
            Log.Information("About to save new verification flow. Purpose: {Purpose}, MobileId: {MobileId}",
                flow.Purpose, flow.MobileNumberId);

            await ctx.SaveChangesAsync(cancellationToken);

            Log.Information("Successfully saved verification flow. FlowId: {FlowId}", flow.UniqueId);

            await transaction.CommitAsync(cancellationToken);

            Log.Information("Transaction committed successfully for flow {FlowId}", flow.UniqueId);

            VerificationFlowEntity? flowWithOtp = await VerificationFlowQueries.GetByUniqueIdWithActiveOtp(ctx, flow.UniqueId, cancellationToken);
            return MapToVerificationFlowRecord(flowWithOtp!);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "CRITICAL: InitiateFlowAsync failed. Purpose: {Purpose}, Error: {Error}",
                cmd.Purpose, ex.Message);
            await transaction.RollbackAsync();
            return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic($"Initiate flow failed: {ex.Message}", ex));
        }
    }

    private static async Task<Result<string, VerificationFlowFailure>> RequestResendOtpAsync(
        EcliptixSchemaContext ctx,
        RequestResendOtpActorEvent cmd,
        CancellationToken cancellationToken)
    {
        try
        {
            VerificationFlowEntity? flow = await VerificationFlowQueries.GetByUniqueId(ctx, cmd.FlowUniqueId, cancellationToken);
            if (flow == null)
                return Result<string, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("Flow not found"));

            return Result<string, VerificationFlowFailure>.Ok("resend_allowed");
        }
        catch (Exception ex)
        {
            return Result<string, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Request resend failed: {ex.Message}"));
        }
    }

    private async Task<Result<Unit, VerificationFlowFailure>> UpdateOtpStatusAsync(
        EcliptixSchemaContext ctx,
        UpdateOtpStatusActorEvent cmd,
        CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction = await ctx.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            string newStatus = ConvertVerificationFlowStatusToOtpStatus(cmd.Status);
            DateTimeOffset utcNow = DateTimeOffset.UtcNow;

            int rowsAffected = await ctx.OtpCodes
                .Where(o => o.UniqueId == cmd.OtpIdentified && !o.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(o => o.Status, newStatus)
                    .SetProperty(o => o.UpdatedAt, utcNow)
                    .SetProperty(o => o.VerifiedAt, newStatus == "used" ? utcNow : (DateTimeOffset?)null),
                    cancellationToken);

            if (rowsAffected == 0)
            {
                await transaction.RollbackAsync();
                return Result<Unit, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("OTP not found"));
            }

            await transaction.CommitAsync(cancellationToken);
            return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync();
            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Update OTP status failed: {ex.Message}"));
        }
    }

    private async Task<Result<MobileNumberQueryRecord, VerificationFlowFailure>> GetMobileNumberAsync(
        EcliptixSchemaContext ctx,
        GetMobileNumberActorEvent cmd,
        CancellationToken cancellationToken)
    {
        try
        {
            MobileNumberEntity? mobile = await MobileNumberQueries.GetByUniqueId(ctx, cmd.MobileNumberIdentifier, cancellationToken);
            if (mobile == null)
                return Result<MobileNumberQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound(VerificationFlowMessageKeys.MobileNotFound));

            return Result<MobileNumberQueryRecord, VerificationFlowFailure>.Ok(new MobileNumberQueryRecord
            {
                MobileNumber = mobile.Number,
                Region = mobile.Region,
                UniqueId = mobile.UniqueId
            });
        }
        catch (Exception ex)
        {
            return Result<MobileNumberQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Get mobile failed: {ex.Message}"));
        }
    }

    private async Task<Result<Unit, VerificationFlowFailure>> UpdateVerificationFlowStatusAsync(
        EcliptixSchemaContext ctx,
        UpdateVerificationFlowStatusActorEvent cmd,
        CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction = await ctx.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            VerificationFlowEntity? flow = await ctx.VerificationFlows
                .Where(f => f.UniqueId == cmd.FlowIdentifier && !f.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken);

            if (flow == null)
            {
                await transaction.RollbackAsync();
                return Result<Unit, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("Flow not found"));
            }

            string newStatus = cmd.Status.ToString().ToLowerInvariant();
            string purpose = flow.Purpose;

            int rowsAffected = await ctx.VerificationFlows
                .Where(f => f.UniqueId == cmd.FlowIdentifier && !f.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(f => f.Status, newStatus)
                    .SetProperty(f => f.UpdatedAt, DateTimeOffset.UtcNow),
                    cancellationToken);

            if (rowsAffected == 0)
            {
                await transaction.RollbackAsync();
                return Result<Unit, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("Flow not found"));
            }

            await transaction.CommitAsync(cancellationToken);

            if (purpose == "password_recovery" && newStatus == "verified" && _membershipPersistorActor != null)
            {
                Log.Information("[UPDATE-FLOW-STATUS] Password recovery flow {FlowId} marked as verified. Sending async request to update membership VerificationFlowId",
                    cmd.FlowIdentifier);

                UpdateMembershipVerificationFlowEvent updateMembershipEvent = new(
                    cmd.FlowIdentifier,
                    purpose,
                    newStatus,
                    cancellationToken);

                _membershipPersistorActor.Tell(updateMembershipEvent);

                Log.Information("[UPDATE-FLOW-STATUS] Membership update request sent for flow {FlowId}", cmd.FlowIdentifier);
            }

            return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync();
            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Update flow status failed: {ex.Message}"));
        }
    }

    private static async Task<Result<string, VerificationFlowFailure>> CheckMobileNumberAvailabilityAsync(
        EcliptixSchemaContext ctx,
        CheckMobileNumberAvailabilityActorEvent cmd,
        CancellationToken cancellationToken)
    {
        try
        {
            bool exists = await MembershipQueries.ExistsByMobileNumberId(
                ctx, cmd.MobileNumberId, cancellationToken);

            return Result<string, VerificationFlowFailure>.Ok(
                exists ? "taken" : "available");
        }
        catch (Exception ex)
        {
            return Result<string, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Check mobile number availability failed: {ex.Message}", ex));
        }
    }

    private static async Task<Result<CreateOtpResult, VerificationFlowFailure>> CreateOtpAsync(
        EcliptixSchemaContext ctx,
        CreateOtpActorEvent cmd,
        CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction = await ctx.Database.BeginTransactionAsync(cancellationToken);

        try
        {
            VerificationFlowEntity? flow = await VerificationFlowQueries.GetByUniqueId(ctx, cmd.OtpRecord.FlowUniqueId, cancellationToken);
            if (flow == null || flow.ExpiresAt <= DateTimeOffset.UtcNow)
            {
                await transaction.RollbackAsync();
                return Result<CreateOtpResult, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("flow_not_found_or_invalid"));
            }

            if (flow.OtpCount >= 5)
            {
                await transaction.RollbackAsync();
                return Result<CreateOtpResult, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.OtpMaxAttemptsReached("max_otp_attempts_reached"));
            }

            Guid requestedOtpId = cmd.OtpRecord.UniqueIdentifier != Guid.Empty
                ? cmd.OtpRecord.UniqueIdentifier
                : Guid.NewGuid();

            if (cmd.OtpRecord.UniqueIdentifier != Guid.Empty)
            {
                bool otpAlreadyExists = await ctx.OtpCodes
                    .Where(o => o.UniqueId == cmd.OtpRecord.UniqueIdentifier && !o.IsDeleted)
                    .AnyAsync(cancellationToken);

                if (otpAlreadyExists)
                {
                    await transaction.CommitAsync(cancellationToken);
                    return Result<CreateOtpResult, VerificationFlowFailure>.Ok(new CreateOtpResult
                    {
                        OtpUniqueId = cmd.OtpRecord.UniqueIdentifier,
                        Outcome = "idempotent"
                    });
                }
            }

            await ctx.OtpCodes
                .Where(o => o.VerificationFlowId == flow.Id && o.Status == "active" && !o.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(o => o.Status, "expired")
                    .SetProperty(o => o.UpdatedAt, DateTimeOffset.UtcNow),
                    cancellationToken);

            OtpCodeEntity otp = new()
            {
                UniqueId = requestedOtpId,
                VerificationFlowId = flow.Id,
                OtpValue = cmd.OtpRecord.OtpHash,
                OtpSalt = cmd.OtpRecord.OtpSalt,
                Status = ConvertVerificationFlowStatusToOtpStatus(cmd.OtpRecord.Status),
                ExpiresAt = cmd.OtpRecord.ExpiresAt,
                AttemptCount = 0,
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow,
                IsDeleted = false
            };

            ctx.OtpCodes.Add(otp);

            await ctx.VerificationFlows
                .Where(f => f.Id == flow.Id)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(f => f.OtpCount, f => f.OtpCount + 1)
                    .SetProperty(f => f.UpdatedAt, DateTimeOffset.UtcNow),
                    cancellationToken);

            await ctx.SaveChangesAsync(cancellationToken);

            await transaction.CommitAsync(cancellationToken);

            return Result<CreateOtpResult, VerificationFlowFailure>.Ok(new CreateOtpResult
            {
                OtpUniqueId = otp.UniqueId,
                Outcome = "created"
            });
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync();
            return Result<CreateOtpResult, VerificationFlowFailure>.Err(
                VerificationFlowFailure.OtpGenerationFailed($"Create OTP failed: {ex.Message}"));
        }
    }

    private async Task<Result<Guid, VerificationFlowFailure>> EnsureMobileNumberAsync(
        EcliptixSchemaContext ctx,
        EnsureMobileNumberActorEvent cmd,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(cmd.MobileNumber))
            return Result<Guid, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Validation("invalid_mobile_number"));

        await using Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction = await ctx.Database.BeginTransactionAsync(cancellationToken);

        try
        {
            MobileNumberEntity? existing = await MobileNumberQueries.GetByNumberAndRegion(
                ctx, cmd.MobileNumber, cmd.RegionCode, cancellationToken);

            if (existing != null)
            {
                await transaction.CommitAsync(cancellationToken);
                return Result<Guid, VerificationFlowFailure>.Ok(existing.UniqueId);
            }

            MobileNumberEntity mobile = new()
            {
                UniqueId = Guid.NewGuid(),
                Number = cmd.MobileNumber,
                Region = cmd.RegionCode,
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow,
                IsDeleted = false
            };

            ctx.MobileNumbers.Add(mobile);
            await ctx.SaveChangesAsync(cancellationToken);

            await transaction.CommitAsync(cancellationToken);

            return Result<Guid, VerificationFlowFailure>.Ok(mobile.UniqueId);
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync();
            return Result<Guid, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Ensure mobile failed: {ex.Message}", ex));
        }
    }

    private static async Task<Result<Guid, VerificationFlowFailure>> VerifyMobileForSecretKeyRecoveryAsync(
        EcliptixSchemaContext ctx,
        VerifyMobileForSecretKeyRecoveryActorEvent cmd,
        CancellationToken cancellationToken)
    {
        try
        {
            MobileNumberEntity? mobile = await MobileNumberQueries.GetByNumberAndRegion(
                ctx, cmd.MobileNumber, cmd.RegionCode, cancellationToken);

            if (mobile == null)
                return Result<Guid, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Validation("mobile_number_not_found"));

            return Result<Guid, VerificationFlowFailure>.Ok(mobile.UniqueId);
        }
        catch (Exception ex)
        {
            return Result<Guid, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Verify mobile recovery failed: {ex.Message}", ex));
        }
    }

    private static Ecliptix.Protobuf.Membership.Membership? MapToProtoMembership(Membership? domainMembership)
    {
        if (domainMembership == null)
            return null;

        return new Ecliptix.Protobuf.Membership.Membership
        {
            UniqueIdentifier = Helpers.GuidToByteString(domainMembership.UniqueId),
            Status = domainMembership.Status switch
            {
                "active" => Ecliptix.Protobuf.Membership.Membership.Types.ActivityStatus.Active,
                _ => Ecliptix.Protobuf.Membership.Membership.Types.ActivityStatus.Inactive
            },
            CreationStatus = domainMembership.CreationStatus switch
            {
                "otp_verified" => Ecliptix.Protobuf.Membership.Membership.Types.CreationStatus.OtpVerified,
                "secure_key_set" => Ecliptix.Protobuf.Membership.Membership.Types.CreationStatus.SecureKeySet,
                "passphrase_set" => Ecliptix.Protobuf.Membership.Membership.Types.CreationStatus.PassphraseSet,
                _ => Ecliptix.Protobuf.Membership.Membership.Types.CreationStatus.OtpVerified
            }
        };
    }

    private static Result<VerificationFlowQueryRecord, VerificationFlowFailure> MapToVerificationFlowRecord(
        VerificationFlowEntity flow)
    {
        OtpCodeEntity? activeOtp = flow.OtpCodes?.FirstOrDefault(o => o.Status == "active" && !o.IsDeleted);
        Option<OtpQueryRecord> otpActive = activeOtp != null
            ? Option<OtpQueryRecord>.Some(new OtpQueryRecord
            {
                UniqueIdentifier = activeOtp.UniqueId,
                FlowUniqueId = flow.UniqueId,
                MobileNumberIdentifier = flow.MobileNumber?.UniqueId ?? Guid.Empty,
                OtpHash = activeOtp.OtpValue,
                OtpSalt = activeOtp.OtpSalt,
                ExpiresAt = activeOtp.ExpiresAt,
                Status = ConvertOtpStatusToVerificationFlowStatus(activeOtp.Status),
                IsActive = activeOtp.Status == "active"
            })
            : Option<OtpQueryRecord>.None;

        VerificationFlowQueryRecord flowRecord = new()
        {
            UniqueIdentifier = flow.UniqueId,
            MobileNumberIdentifier = flow.MobileNumber?.UniqueId ?? Guid.Empty,
            AppDeviceIdentifier = flow.AppDeviceId,
            ConnectId = (uint?)flow.ConnectionId,
            ExpiresAt = flow.ExpiresAt,
            Status = Enum.Parse<VerificationFlowStatus>(flow.Status, true),
            Purpose = ConvertStringToPurpose(flow.Purpose),
            OtpCount = flow.OtpCount,
            OtpActive = otpActive.HasValue ? otpActive.Value : null
        };

        return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Ok(flowRecord);
    }

    private static string ConvertPurposeToString(VerificationPurpose purpose)
    {
        return purpose switch
        {
            VerificationPurpose.Registration => "registration",
            VerificationPurpose.Login => "login",
            VerificationPurpose.PasswordRecovery => "password_recovery",
            _ => "unspecified"
        };
    }

    private static VerificationPurpose ConvertStringToPurpose(string purpose)
    {
        return purpose.ToLowerInvariant() switch
        {
            "registration" => VerificationPurpose.Registration,
            "login" => VerificationPurpose.Login,
            "password_recovery" => VerificationPurpose.PasswordRecovery,
            _ => VerificationPurpose.Registration
        };
    }

    private static string ConvertVerificationFlowStatusToOtpStatus(VerificationFlowStatus status)
    {
        return status switch
        {
            VerificationFlowStatus.Pending => "active",
            VerificationFlowStatus.Verified => "used",
            VerificationFlowStatus.Failed => "invalid",
            VerificationFlowStatus.Expired => "expired",
            VerificationFlowStatus.MaxAttemptsReached => "invalid",
            _ => "expired"
        };
    }

    private static VerificationFlowStatus ConvertOtpStatusToVerificationFlowStatus(string otpStatus)
    {
        return otpStatus.ToLowerInvariant() switch
        {
            "active" => VerificationFlowStatus.Pending,
            "used" => VerificationFlowStatus.Verified,
            "invalid" => VerificationFlowStatus.Failed,
            _ => VerificationFlowStatus.Expired
        };
    }


    protected override VerificationFlowFailure MapDbException(DbException ex)
    {
        if (ex is SqlException sqlEx)
        {
            return sqlEx.Number switch
            {
                2627 or 2601 => VerificationFlowFailure.ConcurrencyConflict($"Unique constraint violation: {sqlEx.Message}"),
                547 => VerificationFlowFailure.Validation($"Foreign key constraint violation: {sqlEx.Message}"),
                1205 => VerificationFlowFailure.ConcurrencyConflict($"Deadlock detected: {sqlEx.Message}"),
                -2 => VerificationFlowFailure.PersistorAccess("Command timeout occurred", sqlEx),
                2 => VerificationFlowFailure.PersistorAccess("Network error occurred", sqlEx),
                18456 => VerificationFlowFailure.PersistorAccess("Authentication failed", sqlEx),
                _ => VerificationFlowFailure.PersistorAccess($"Database error (Code: {sqlEx.Number}): {sqlEx.Message}", sqlEx)
            };
        }

        return VerificationFlowFailure.PersistorAccess("Database operation failed", ex);
    }

    protected override VerificationFlowFailure CreateTimeoutFailure(TimeoutException ex)
    {
        return VerificationFlowFailure.PersistorAccess("Database operation timed out", ex);
    }

    protected override VerificationFlowFailure CreateGenericFailure(Exception ex)
    {
        return VerificationFlowFailure.Generic($"Unexpected error in verification flow persistor: {ex.Message}", ex);
    }

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return PersistorSupervisorStrategy.CreateStrategy();
    }
}
