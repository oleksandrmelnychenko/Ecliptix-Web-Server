using System.Data.Common;
using Akka.Actor;
using Ecliptix.Domain.Account.ActorEvents;
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
using Serilog;
using Membership = Ecliptix.Domain.Schema.Entities.MembershipEntity;

namespace Ecliptix.Domain.Memberships.Persistors;

public class VerificationFlowPersistorActor : PersistorBase<VerificationFlowFailure>
{
    public VerificationFlowPersistorActor(
        IDbContextFactory<EcliptixSchemaContext> dbContextFactory)
        : base(dbContextFactory)
    {
        Become(Ready);
    }

    public static Props Build(IDbContextFactory<EcliptixSchemaContext> dbContextFactory)
    {
        return Props.Create(() => new VerificationFlowPersistorActor(dbContextFactory));
    }

    private void Ready()
    {
        Receive<InitiateFlowAndReturnStateActorEvent>(actorEvent =>
            ExecuteWithContext(ctx => InitiateFlowAsync(ctx, actorEvent), "InitiateVerificationFlow")
                .PipeTo(Sender));
        Receive<RequestResendOtpActorEvent>(actorEvent =>
            ExecuteWithContext(ctx => RequestResendOtpAsync(ctx, actorEvent), "RequestResendOtp").PipeTo(Sender));
        Receive<UpdateVerificationFlowStatusActorEvent>(actorEvent =>
            ExecuteWithContext(ctx => UpdateVerificationFlowStatusAsync(ctx, actorEvent),
                    "UpdateVerificationFlowStatus")
                .PipeTo(Sender));
        Receive<EnsureMobileNumberActorEvent>(actorEvent =>
            ExecuteWithContext(ctx => EnsureMobileNumberAsync(ctx, actorEvent), "EnsureMobileNumber")
                .PipeTo(Sender));
        Receive<VerifyMobileForSecretKeyRecoveryActorEvent>(actorEvent =>
            ExecuteWithContext(ctx => VerifyMobileForSecretKeyRecoveryAsync(ctx, actorEvent),
                    "VerifyMobileForSecretKeyRecovery")
                .PipeTo(Sender));
        Receive<GetMobileNumberActorEvent>(actorEvent =>
            ExecuteWithContext(ctx => GetMobileNumberAsync(ctx, actorEvent), "GetMobileNumber").PipeTo(Sender));
        Receive<CreateOtpActorEvent>(actorEvent =>
            ExecuteWithContext(ctx => CreateOtpAsync(ctx, actorEvent), "CreateOtp").PipeTo(Sender));
        Receive<UpdateOtpStatusActorEvent>(actorEvent =>
            ExecuteWithContext(ctx => UpdateOtpStatusAsync(ctx, actorEvent), "UpdateOtpStatus").PipeTo(Sender));
        Receive<ValidatePasswordRecoveryFlowEvent>(actorEvent =>
            ExecuteWithContext(ctx => ValidatePasswordRecoveryFlowAsync(ctx, actorEvent), "ValidatePasswordRecoveryFlow")
                .PipeTo(Sender));
        Receive<ExpirePasswordRecoveryFlowsEvent>(actorEvent =>
            ExecuteWithContext(ctx => ExpirePasswordRecoveryFlowsAsync(ctx, actorEvent), "ExpirePasswordRecoveryFlows")
                .PipeTo(Sender));
        Receive<CheckExistingMembershipActorEvent>(actorEvent =>
            ExecuteWithContext(ctx => CheckExistingMembershipAsync(ctx, actorEvent), "CheckExistingMembership")
                .PipeTo(Sender));
    }

    private static async Task<Result<VerificationFlowQueryRecord, VerificationFlowFailure>> InitiateFlowAsync(
        EcliptixSchemaContext ctx, InitiateFlowAndReturnStateActorEvent cmd)
    {
        await using Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction = await ctx.Database.BeginTransactionAsync();

        try
        {
            MobileNumberEntity? mobile = await MobileNumberQueries.GetByUniqueId(ctx, cmd.MobileNumberUniqueId);
            if (mobile == null)
            {
                await transaction.RollbackAsync();
                return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("mobile_number_not_found"));
            }

            bool deviceExists = await DeviceQueries.ExistsByUniqueId(ctx, cmd.AppDeviceId);
            if (!deviceExists)
            {
                await transaction.RollbackAsync();
                return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("device_not_found"));
            }

            VerificationFlowEntity? existingActiveFlow = await VerificationFlowQueries.GetActiveFlowForRecovery(
                ctx, cmd.MobileNumberUniqueId, cmd.AppDeviceId,
                ConvertPurposeToString(cmd.Purpose));

            if (existingActiveFlow != null)
            {
                await ctx.VerificationFlows
                    .Where(vf => vf.Id == existingActiveFlow.Id)
                    .ExecuteUpdateAsync(setters => setters
                        .SetProperty(vf => vf.ConnectionId, (long?)cmd.ConnectId)
                        .SetProperty(vf => vf.UpdatedAt, DateTime.UtcNow));

                await ctx.OtpCodes
                    .Where(o => o.VerificationFlowId == existingActiveFlow.Id &&
                                o.Status == "active" &&
                                !o.IsDeleted)
                    .ExecuteUpdateAsync(setters => setters
                        .SetProperty(o => o.Status, "expired")
                        .SetProperty(o => o.UpdatedAt, DateTime.UtcNow));

                await transaction.CommitAsync();

                existingActiveFlow.ConnectionId = cmd.ConnectId;
                existingActiveFlow.UpdatedAt = DateTime.UtcNow;
                existingActiveFlow.MobileNumber = mobile;
                existingActiveFlow.OtpCodes = new List<OtpCodeEntity>();

                return MapToVerificationFlowRecord(existingActiveFlow);
            }

            if (cmd.Purpose == VerificationPurpose.PasswordRecovery)
            {
                Log.Information("Password recovery flow initiated for mobile ID {MobileId}", mobile.Id);

                int recoveryCount = await VerificationFlowQueries.CountRecentPasswordRecovery(
                    ctx, mobile.Id, DateTime.UtcNow.AddHours(-1));

                Log.Information("Recent password recovery count: {Count} for mobile ID {MobileId}", recoveryCount, mobile.Id);

                if (recoveryCount >= 3)
                {
                    await transaction.RollbackAsync();
                    return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.RateLimitExceeded("password_recovery_rate_limit_exceeded"));
                }

                List<VerificationFlowEntity> oldPendingFlows = await ctx.VerificationFlows
                    .Where(vf => vf.MobileNumberId == mobile.Id &&
                                 vf.Purpose == "password_recovery" &&
                                 vf.Status == "pending" &&
                                 !vf.IsDeleted)
                    .ToListAsync();

                Log.Information("Found {Count} old pending password recovery flows to expire for mobile ID {MobileId}",
                    oldPendingFlows.Count, mobile.Id);

                foreach (VerificationFlowEntity oldFlow in oldPendingFlows)
                {
                    oldFlow.Status = "expired";
                    oldFlow.UpdatedAt = DateTime.UtcNow;
                }

                Log.Information("Updated {Count} old flows to expired status", oldPendingFlows.Count);
            }

            int mobileFlowCount = await VerificationFlowQueries.CountRecentByMobileId(
                ctx, mobile.Id, DateTime.UtcNow.AddHours(-1));
            if (mobileFlowCount >= 30)
            {
                await transaction.RollbackAsync();
                return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.RateLimitExceeded("rate_limit_exceeded"));
            }

            int deviceFlowCount = await VerificationFlowQueries.CountRecentByDevice(
                ctx, cmd.AppDeviceId, DateTime.UtcNow.AddHours(-1));
            if (deviceFlowCount >= 10)
            {
                await transaction.RollbackAsync();
                return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.RateLimitExceeded("device_rate_limit_exceeded"));
            }

            VerificationFlowEntity flow = new()
            {
                UniqueId = Guid.NewGuid(),
                MobileNumberId = mobile.Id,
                AppDeviceId = cmd.AppDeviceId,
                Purpose = ConvertPurposeToString(cmd.Purpose),
                Status = "pending",
                ExpiresAt = DateTime.UtcNow.AddMinutes(15),
                ConnectionId = cmd.ConnectId,
                OtpCount = 0,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                IsDeleted = false
            };

            ctx.VerificationFlows.Add(flow);
            Log.Information("About to save new verification flow. Purpose: {Purpose}, MobileId: {MobileId}",
                flow.Purpose, flow.MobileNumberId);

            await ctx.SaveChangesAsync();

            Log.Information("Successfully saved verification flow. FlowId: {FlowId}", flow.UniqueId);

            await transaction.CommitAsync();

            Log.Information("Transaction committed successfully for flow {FlowId}", flow.UniqueId);

            VerificationFlowEntity? flowWithOtp = await VerificationFlowQueries.GetByUniqueIdWithActiveOtp(ctx, flow.UniqueId);
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
        EcliptixSchemaContext ctx, RequestResendOtpActorEvent cmd)
    {
        try
        {
            VerificationFlowEntity? flow = await VerificationFlowQueries.GetByUniqueId(ctx, cmd.FlowUniqueId);
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
        EcliptixSchemaContext ctx, UpdateOtpStatusActorEvent cmd)
    {
        try
        {
            int rowsAffected = await ctx.OtpCodes
                .Where(o => o.UniqueId == cmd.OtpIdentified && !o.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(o => o.Status, ConvertVerificationFlowStatusToOtpStatus(cmd.Status))
                    .SetProperty(o => o.UpdatedAt, DateTime.UtcNow));

            if (rowsAffected == 0)
                return Result<Unit, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("OTP not found"));

            return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Update OTP status failed: {ex.Message}"));
        }
    }

    private async Task<Result<MobileNumberQueryRecord, VerificationFlowFailure>> GetMobileNumberAsync(
        EcliptixSchemaContext ctx, GetMobileNumberActorEvent cmd)
    {
        try
        {
            MobileNumberEntity? mobile = await MobileNumberQueries.GetByUniqueId(ctx, cmd.MobileNumberIdentifier);
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

    private async Task<Result<int, VerificationFlowFailure>> UpdateVerificationFlowStatusAsync(
        EcliptixSchemaContext ctx, UpdateVerificationFlowStatusActorEvent cmd)
    {
        try
        {
            int rowsAffected = await ctx.VerificationFlows
                .Where(f => f.UniqueId == cmd.FlowIdentifier && !f.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(f => f.Status, cmd.Status.ToString().ToLowerInvariant())
                    .SetProperty(f => f.UpdatedAt, DateTime.UtcNow));

            if (rowsAffected == 0)
                return Result<int, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("Flow not found"));

            return Result<int, VerificationFlowFailure>.Ok(rowsAffected);
        }
        catch (Exception ex)
        {
            return Result<int, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Update flow status failed: {ex.Message}"));
        }
    }

    private static async Task<Result<ExistingMembershipResult, VerificationFlowFailure>> CheckExistingMembershipAsync(
        EcliptixSchemaContext ctx, CheckExistingMembershipActorEvent cmd)
    {
        try
        {
            Membership? membership = await AccountQueries.GetByMobileUniqueId(
                ctx, cmd.MobileNumberId);

            if (membership == null)
            {
                return Result<ExistingMembershipResult, VerificationFlowFailure>.Ok(new ExistingMembershipResult
                {
                    MembershipExists = false,
                    Membership = null
                });
            }

            return Result<ExistingMembershipResult, VerificationFlowFailure>.Ok(new ExistingMembershipResult
            {
                MembershipExists = true,
                Membership = MapToProtoMembership(membership)
            });
        }
        catch (Exception ex)
        {
            return Result<ExistingMembershipResult, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Check existing membership failed: {ex.Message}", ex));
        }
    }

    private static async Task<Result<CreateOtpResult, VerificationFlowFailure>> CreateOtpAsync(
        EcliptixSchemaContext ctx, CreateOtpActorEvent cmd)
    {
        await using Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction = await ctx.Database.BeginTransactionAsync();

        try
        {
            VerificationFlowEntity? flow = await VerificationFlowQueries.GetByUniqueId(ctx, cmd.OtpRecord.FlowUniqueId);
            if (flow == null || flow.ExpiresAt <= DateTime.UtcNow)
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

            await ctx.OtpCodes
                .Where(o => o.VerificationFlowId == flow.Id && o.Status == "active" && !o.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(o => o.Status, "expired")
                    .SetProperty(o => o.UpdatedAt, DateTime.UtcNow));

            OtpCodeEntity otp = new()
            {
                UniqueId = Guid.NewGuid(),
                VerificationFlowId = flow.Id,
                OtpValue = cmd.OtpRecord.OtpHash,
                OtpSalt = cmd.OtpRecord.OtpSalt,
                Status = ConvertVerificationFlowStatusToOtpStatus(cmd.OtpRecord.Status),
                ExpiresAt = cmd.OtpRecord.ExpiresAt,
                AttemptCount = 0,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                IsDeleted = false
            };

            ctx.OtpCodes.Add(otp);

            await ctx.VerificationFlows
                .Where(f => f.Id == flow.Id)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(f => f.OtpCount, f => f.OtpCount + 1)
                    .SetProperty(f => f.UpdatedAt, DateTime.UtcNow));

            await ctx.SaveChangesAsync();

            await transaction.CommitAsync();

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
        EcliptixSchemaContext ctx, EnsureMobileNumberActorEvent cmd)
    {
        if (string.IsNullOrWhiteSpace(cmd.MobileNumber))
            return Result<Guid, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Validation("invalid_mobile_number"));

        await using Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction = await ctx.Database.BeginTransactionAsync();

        try
        {
            MobileNumberEntity? existing = await MobileNumberQueries.GetByNumberAndRegion(
                ctx, cmd.MobileNumber, cmd.RegionCode);

            if (existing != null)
            {
                await transaction.CommitAsync();
                return Result<Guid, VerificationFlowFailure>.Ok(existing.UniqueId);
            }

            MobileNumberEntity mobile = new()
            {
                UniqueId = Guid.NewGuid(),
                Number = cmd.MobileNumber,
                Region = cmd.RegionCode,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                IsDeleted = false
            };

            ctx.MobileNumbers.Add(mobile);
            await ctx.SaveChangesAsync();

            await transaction.CommitAsync();

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
        EcliptixSchemaContext ctx, VerifyMobileForSecretKeyRecoveryActorEvent cmd)
    {
        try
        {
            MobileNumberEntity? mobile = await MobileNumberQueries.GetByNumberAndRegion(
                ctx, cmd.MobileNumber, cmd.RegionCode);

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

    private async Task<Result<PasswordRecoveryFlowValidation, VerificationFlowFailure>> ValidatePasswordRecoveryFlowAsync(
        EcliptixSchemaContext ctx, ValidatePasswordRecoveryFlowEvent cmd)
    {
        try
        {
            DateTime tenMinutesAgo = DateTime.UtcNow.AddMinutes(-10);

            VerificationFlowEntity? recoveryFlow = await ctx.VerificationFlows
                .Join(ctx.Memberships,
                    vf => vf.UniqueId,
                    m => m.VerificationFlowId,
                    (vf, m) => new { VerificationFlow = vf, Membership = m })
                .Where(x => x.Membership.UniqueId == cmd.MembershipIdentifier &&
                            x.VerificationFlow.Purpose == "password_recovery" &&
                            x.VerificationFlow.Status == "verified" &&
                            x.VerificationFlow.UpdatedAt >= tenMinutesAgo &&
                            !x.VerificationFlow.IsDeleted &&
                            !x.Membership.IsDeleted)
                .Select(x => x.VerificationFlow)
                .OrderByDescending(vf => vf.UpdatedAt)
                .FirstOrDefaultAsync();

            if (recoveryFlow == null)
            {
                return Result<PasswordRecoveryFlowValidation, VerificationFlowFailure>.Ok(
                    new PasswordRecoveryFlowValidation(false, null));
            }

            return Result<PasswordRecoveryFlowValidation, VerificationFlowFailure>.Ok(
                new PasswordRecoveryFlowValidation(true, recoveryFlow.UniqueId));
        }
        catch (Exception ex)
        {
            return Result<PasswordRecoveryFlowValidation, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Validate password recovery flow failed: {ex.Message}"));
        }
    }

    private async Task<Result<Unit, VerificationFlowFailure>> ExpirePasswordRecoveryFlowsAsync(
        EcliptixSchemaContext ctx, ExpirePasswordRecoveryFlowsEvent cmd)
    {
        try
        {
            await ctx.VerificationFlows
                .Join(ctx.Memberships,
                    vf => vf.UniqueId,
                    m => m.VerificationFlowId,
                    (vf, m) => new { VerificationFlow = vf, Membership = m })
                .Where(x => x.Membership.UniqueId == cmd.MembershipIdentifier &&
                            x.VerificationFlow.Purpose == "password_recovery" &&
                            x.VerificationFlow.Status == "verified" &&
                            !x.VerificationFlow.IsDeleted)
                .Select(x => x.VerificationFlow)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(vf => vf.Status, "expired")
                    .SetProperty(vf => vf.UpdatedAt, DateTime.UtcNow));

            return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Expire password recovery flows failed: {ex.Message}"));
        }
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