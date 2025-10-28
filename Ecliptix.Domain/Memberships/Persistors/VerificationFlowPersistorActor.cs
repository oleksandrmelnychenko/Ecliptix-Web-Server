using System.Data.Common;
using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents.Account;
using Ecliptix.Domain.Memberships.ActorEvents.Common;
using Ecliptix.Domain.Memberships.ActorEvents.MobileNumber;
using Ecliptix.Domain.Memberships.ActorEvents.Otp;
using Ecliptix.Domain.Memberships.ActorEvents.VerificationFlow;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.CompiledQueries;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.QueryResults;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Configuration;
using Google.Protobuf;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Options;
using Serilog;
using MembershipEntity = Ecliptix.Domain.Schema.Entities.MembershipEntity;
using ProtoMembership = Ecliptix.Protobuf.Membership.Membership;

namespace Ecliptix.Domain.Memberships.Persistors;

public class VerificationFlowPersistorActor : PersistorBase<VerificationFlowFailure>
{
    private readonly IActorRef? _membershipPersistorActor;
    private readonly IOptionsMonitor<SecurityConfiguration> _securityConfig;

    public VerificationFlowPersistorActor(
        IDbContextFactory<EcliptixSchemaContext> dbContextFactory,
        IOptionsMonitor<SecurityConfiguration> securityConfig,
        IActorRef? membershipPersistorActor = null)
        : base(dbContextFactory)
    {
        _membershipPersistorActor = membershipPersistorActor;
        _securityConfig = securityConfig;
        Become(Ready);
    }

    public static Props Build(IDbContextFactory<EcliptixSchemaContext> dbContextFactory,
        IOptionsMonitor<SecurityConfiguration> securityConfig, IActorRef? membershipPersistorActor = null)
    {
        return Props.Create(() =>
            new VerificationFlowPersistorActor(dbContextFactory, securityConfig, membershipPersistorActor));
    }

    private void Ready()
    {
        RegisterHandlers();
        Receive<Result<Unit, VerificationFlowFailure>>(result =>
        {
            if (result.IsErr)
            {
                Log.Warning("[UPDATE-FLOW-STATUS] Membership update acknowledgement received with error: {Error}",
                    result.UnwrapErr().Message);
            }
        });
    }

    private void RegisterHandlers()
    {
        ReceivePersistorCommand<InitiateFlowAndReturnStateActorEvent, VerificationFlowQueryRecord>(
            InitiateFlowAsync,
            "InitiateVerificationFlow");

        ReceivePersistorCommand<RequestResendOtpActorEvent, (string Outcome, uint RemainingSeconds)>(
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

        ReceivePersistorCommand<CheckMobileNumberAvailabilityActorEvent, MobileNumberAvailabilityResponse>(
            CheckMobileNumberAvailabilityAsync,
            "CheckMobileNumberAvailability");

        ReceivePersistorCommand<CheckExistingMembershipActorEvent, ExistingMembershipResult>(
            CheckExistingMembershipAsync,
            "CheckExistingMembership");

        ReceivePersistorCommand<IncrementOtpAttemptCountActorEvent, Unit>(
            IncrementOtpAttemptCountAsync,
            "IncrementOtpAttemptCount");

        ReceivePersistorCommand<LogFailedOtpAttemptActorEvent, Unit>(
            LogFailedAttemptAsync,
            "LogFailedAttempt");

        ReceivePersistorCommand<GetOtpAttemptCountActorEvent, short>(
            GetOtpAttemptCountAsync,
            "GetOtpAttemptCount");
    }

    private void ReceivePersistorCommand<TMessage, TResult>(
        Func<EcliptixSchemaContext, TMessage, CancellationToken, Task<Result<TResult, VerificationFlowFailure>>>
            handler,
        string operationName)
        where TMessage : class, ICancellableActorEvent
    {
        Receive<TMessage>(message =>
        {
            IActorRef replyTo = Sender;
            CancellationToken messageToken = message.CancellationToken;

            Task<Result<TResult, VerificationFlowFailure>> Operation(EcliptixSchemaContext schemeContext,
                CancellationToken cancellationToken)
            {
                CancellationToken effectiveToken = CombineCancellationTokens(cancellationToken, messageToken,
                    out CancellationTokenSource? linkedSource);
                try
                {
                    return handler(schemeContext, message, effectiveToken);
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

        switch (firstActive)
        {
            case false when !secondActive:
                return CancellationToken.None;
            case false:
                return second;
        }

        if (!secondActive)
        {
            return first;
        }

        linkedSource = CancellationTokenSource.CreateLinkedTokenSource(first, second);
        return linkedSource.Token;
    }

    private async Task<Result<VerificationFlowQueryRecord, VerificationFlowFailure>> InitiateFlowAsync(
        EcliptixSchemaContext schemeContext,
        InitiateFlowAndReturnStateActorEvent cmd,
        CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await schemeContext.Database.BeginTransactionAsync(cancellationToken);

        try
        {
            VerificationFlowPersistorSettings
                persistorSettings = _securityConfig.CurrentValue.VerificationFlowPersistor;
            Option<MobileNumberEntity> mobileOpt =
                await MobileNumberQueries.GetByUniqueId(schemeContext, cmd.MobileNumberUniqueId, cancellationToken);
            if (!mobileOpt.HasValue)
            {
                Log.Warning("[InitiateFlow] Mobile number not found: {MobileNumberId}", cmd.MobileNumberUniqueId);
                await transaction.RollbackAsync();
                return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.FromMobileNumber(MobileNumberFailure.NotFound()));
            }

            MobileNumberEntity mobile = mobileOpt.Value!;

            bool deviceExists = await DeviceQueries.ExistsByUniqueId(schemeContext, cmd.AppDeviceId, cancellationToken);
            if (!deviceExists)
            {
                Log.Warning("[InitiateFlow] Device not found: {DeviceId}", cmd.AppDeviceId);
                await transaction.RollbackAsync();
                return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Validation("Device not found"));
            }

            Option<VerificationFlowEntity> existingActiveFlowOpt =
                await VerificationFlowQueries.GetActiveFlowForRecovery(
                    schemeContext,
                    cmd.MobileNumberUniqueId,
                    cmd.AppDeviceId,
                    cmd.Purpose,
                    cancellationToken);

            if (existingActiveFlowOpt.HasValue)
            {
                VerificationFlowEntity existingActiveFlow = existingActiveFlowOpt.Value!;
                DateTimeOffset now = DateTimeOffset.UtcNow;

                await schemeContext.VerificationFlows
                    .Where(vf => vf.Id == existingActiveFlow.Id)
                    .ExecuteUpdateAsync(setters => setters
                            .SetProperty(vf => vf.Status, VerificationFlowStatus.Expired)
                            .SetProperty(vf => vf.ConnectionId, (long?)null)
                            .SetProperty(vf => vf.ExpiresAt, now)
                            .SetProperty(vf => vf.UpdatedAt, now),
                        cancellationToken);

                await schemeContext.OtpCodes
                    .Where(o => o.VerificationFlowId == existingActiveFlow.Id &&
                                o.Status == OtpStatus.Active &&
                                !o.IsDeleted)
                    .ExecuteUpdateAsync(setters => setters
                            .SetProperty(o => o.Status, OtpStatus.Expired)
                            .SetProperty(o => o.UpdatedAt, now),
                        cancellationToken);

                Log.Information(
                    "[verification.flow.recovered] Expired lingering flow {FlowId} before creating a new one",
                    existingActiveFlow.UniqueId);
            }

            if (cmd.Purpose == VerificationPurpose.PasswordRecovery)
            {
                Log.Information(
                    "[INITIATE-PASSWORD-RECOVERY] Password recovery flow initiated for mobile ID {MobileId}",
                    mobile.UniqueId);

                DateTimeOffset recoveryLookbackTime =
                    DateTimeOffset.UtcNow - persistorSettings.PasswordRecoveryLookback;

                int recoveryCountByMobile = await VerificationFlowQueries.CountRecentPasswordRecovery(
                    schemeContext, mobile.UniqueId, recoveryLookbackTime, cancellationToken);

                int recoveryCountByDevice = await schemeContext.VerificationFlows
                    .Where(f => f.AppDeviceId == cmd.AppDeviceId &&
                                f.Purpose == VerificationPurpose.PasswordRecovery &&
                                f.CreatedAt >= recoveryLookbackTime &&
                                !f.IsDeleted)
                    .AsNoTracking()
                    .CountAsync(cancellationToken);

                Log.Information(
                    "[INITIATE-PASSWORD-RECOVERY] Recent password recovery counts - Mobile: {MobileCount}, Device: {DeviceCount} for mobile ID {MobileId}",
                    recoveryCountByMobile, recoveryCountByDevice, mobile.UniqueId);

                int maxAttemptsByMobile = _securityConfig.CurrentValue.VerificationFlowLimits
                    .PasswordRecoveryAttemptsPerHourPerMobile;
                int maxAttemptsByDevice = _securityConfig.CurrentValue.VerificationFlowLimits
                    .PasswordRecoveryAttemptsPerHourPerDevice;

                if (recoveryCountByMobile >= maxAttemptsByMobile || recoveryCountByDevice >= maxAttemptsByDevice)
                {
                    Log.Warning(
                        "[InitiateFlow] Password recovery rate limit exceeded. Mobile: {MobileCount}/{MaxMobile}, Device: {DeviceCount}/{MaxDevice}",
                        recoveryCountByMobile, maxAttemptsByMobile, recoveryCountByDevice, maxAttemptsByDevice);
                    await transaction.RollbackAsync();
                    return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.RateLimitExceeded());
                }

                List<VerificationFlowEntity> oldActiveFlows = await schemeContext.VerificationFlows
                    .Where(vf => vf.MobileNumberId == mobile.UniqueId &&
                                 vf.Purpose == VerificationPurpose.PasswordRecovery &&
                                 (vf.Status == VerificationFlowStatus.Pending || vf.Status == VerificationFlowStatus.Verified) &&
                                 !vf.IsDeleted)
                    .ToListAsync(cancellationToken);

                Log.Information(
                    "[INITIATE-PASSWORD-RECOVERY] Found {Count} old password recovery flows (pending + verified) to expire for mobile ID {MobileId}",
                    oldActiveFlows.Count, mobile.UniqueId);

                if (oldActiveFlows.Count > 0)
                {
                    foreach (VerificationFlowEntity oldFlow in oldActiveFlows)
                    {
                        VerificationFlowStatus oldStatus = oldFlow.Status;
                        oldFlow.Status = VerificationFlowStatus.Expired;
                        oldFlow.UpdatedAt = DateTimeOffset.UtcNow;
                        Log.Information(
                            "[INITIATE-PASSWORD-RECOVERY] Expiring flow {FlowId} with status '{OldStatus}' for mobile ID {MobileId}",
                            oldFlow.UniqueId, oldStatus, mobile.UniqueId);
                    }

                    Log.Information(
                        "[INITIATE-PASSWORD-RECOVERY] Successfully expired {Count} old password recovery flows",
                        oldActiveFlows.Count);
                }
            }

            DateTimeOffset rateLimitLookback = DateTimeOffset.UtcNow - persistorSettings.RateLimitLookback;

            int mobileFlowCount = await VerificationFlowQueries.CountRecentByMobileId(
                schemeContext, mobile.UniqueId, rateLimitLookback, cancellationToken);
            if (mobileFlowCount >= persistorSettings.MaxFlowsPerHourPerMobile)
            {
                Log.Warning("[InitiateFlow] Mobile rate limit exceeded. Count: {Count}, Max: {Max}, Mobile: {MobileId}",
                    mobileFlowCount, persistorSettings.MaxFlowsPerHourPerMobile, mobile.UniqueId);
                await transaction.RollbackAsync();
                return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.RateLimitExceeded());
            }

            int deviceFlowCount = await VerificationFlowQueries.CountRecentByDevice(
                schemeContext, cmd.AppDeviceId, rateLimitLookback, cancellationToken);
            if (deviceFlowCount >= persistorSettings.MaxFlowsPerHourPerDevice)
            {
                Log.Warning("[InitiateFlow] Device rate limit exceeded. Count: {Count}, Max: {Max}, Device: {DeviceId}",
                    deviceFlowCount, persistorSettings.MaxFlowsPerHourPerDevice, cmd.AppDeviceId);
                await transaction.RollbackAsync();
                return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.DeviceRateLimitExceeded());
            }

            VerificationFlowEntity flow = new()
            {
                UniqueId = Guid.NewGuid(),
                MobileNumberId = mobile.UniqueId,
                AppDeviceId = cmd.AppDeviceId,
                Purpose = cmd.Purpose,
                Status = VerificationFlowStatus.Pending,
                ExpiresAt = DateTimeOffset.UtcNow + persistorSettings.FlowExpiration,
                ConnectionId = cmd.ConnectId,
                OtpCount = 0,
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow,
                IsDeleted = false
            };

            schemeContext.VerificationFlows.Add(flow);
            Log.Information("About to save new verification flow. Purpose: {Purpose}, MobileId: {MobileId}",
                flow.Purpose, flow.MobileNumberId);

            await schemeContext.SaveChangesAsync(cancellationToken);

            Log.Information("Successfully saved verification flow. FlowId: {FlowId}", flow.UniqueId);

            await transaction.CommitAsync(cancellationToken);

            Log.Information("Transaction committed successfully for flow {FlowId}", flow.UniqueId);

            Option<VerificationFlowEntity> flowWithOtpOpt =
                await VerificationFlowQueries.GetByUniqueIdWithActiveOtp(schemeContext, flow.UniqueId,
                    cancellationToken);
            if (!flowWithOtpOpt.HasValue)
            {
                Log.Error("[InitiateFlow] Flow not found after creation: {FlowId}", flow.UniqueId);
                return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.FlowNotFoundAfterCreation());
            }

            return MapToVerificationFlowRecord(flowWithOtpOpt.Value!);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[InitiateFlow] Operation failed. Purpose: {Purpose}",
                cmd.Purpose);
            await transaction.RollbackAsync();
            return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InitiateFlowFailed(ex));
        }
    }

    private async Task<Result<(string Outcome, uint RemainingSeconds), VerificationFlowFailure>> RequestResendOtpAsync(
        EcliptixSchemaContext schemeContext,
        RequestResendOtpActorEvent cmd,
        CancellationToken cancellationToken)
    {
        try
        {
            Option<VerificationFlowEntity> flowOpt =
                await VerificationFlowQueries.GetByUniqueId(schemeContext, cmd.FlowUniqueId, cancellationToken);
            if (!flowOpt.HasValue)
            {
                Log.Warning("[RequestResend] Flow not found: {FlowId}", cmd.FlowUniqueId);
                return Result<(string, uint), VerificationFlowFailure>.Err(
                    VerificationFlowFailure.FlowNotFound());
            }

            VerificationFlowEntity flow = flowOpt.Value!;

            if (flow.ResendAvailableAt.HasValue)
            {
                DateTimeOffset now = DateTimeOffset.UtcNow;
                if (now < flow.ResendAvailableAt.Value)
                {
                    uint remainingSeconds = (uint)Math.Ceiling((flow.ResendAvailableAt.Value - now).TotalSeconds);
                    return Result<(string, uint), VerificationFlowFailure>.Ok(
                        (VerificationFlowMessageKeys.ResendCooldown, remainingSeconds));
                }
            }

            if (flow.OtpCount >= _securityConfig.CurrentValue.VerificationFlowLimits.MaxOtpSendsPerFlow)
            {
                return Result<(string, uint), VerificationFlowFailure>.Ok(
                    (VerificationFlowMessageKeys.OtpMaxAttemptsReached, 0));
            }

            return Result<(string, uint), VerificationFlowFailure>.Ok(
                (VerificationFlowMessageKeys.ResendAllowed, 0));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[RequestResend] Operation failed for flow: {FlowId}", cmd.FlowUniqueId);
            return Result<(string, uint), VerificationFlowFailure>.Err(
                VerificationFlowFailure.RequestResendFailed(ex));
        }
    }

    private async Task<Result<Unit, VerificationFlowFailure>> UpdateOtpStatusAsync(
        EcliptixSchemaContext schemeContext,
        UpdateOtpStatusActorEvent cmd,
        CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await schemeContext.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            DateTimeOffset utcNow = DateTimeOffset.UtcNow;

            OtpCodeEntity? otp = await schemeContext.OtpCodes
                .Where(o => o.UniqueId == cmd.OtpIdentified && !o.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken);

            if (otp == null)
            {
                Log.Warning("[UpdateOtpStatus] OTP not found: {OtpId}", cmd.OtpIdentified);
                await transaction.RollbackAsync();
                return Result<Unit, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.FromOtp(OtpFailure.NotFound()));
            }

            otp.Status = cmd.Status;
            otp.UpdatedAt = utcNow;
            if (cmd.Status == OtpStatus.Used)
            {
                otp.VerifiedAt = utcNow;
            }

            if (cmd.Status == OtpStatus.Expired)
            {
                int cooldownSeconds = _securityConfig.CurrentValue.VerificationFlow.ResendCooldownBufferSeconds;
                DateTimeOffset resendAvailableAt = utcNow.AddSeconds(cooldownSeconds);

                await schemeContext.VerificationFlows
                    .Where(vf => vf.Id == otp.VerificationFlowId && !vf.IsDeleted)
                    .ExecuteUpdateAsync(setters => setters
                            .SetProperty(vf => vf.ResendAvailableAt, resendAvailableAt)
                            .SetProperty(vf => vf.UpdatedAt, utcNow),
                        cancellationToken);
            }

            await schemeContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[UpdateOtpStatus] Operation failed for OTP: {OtpId}", cmd.OtpIdentified);
            await transaction.RollbackAsync();
            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.UpdateOtpStatusFailed(ex));
        }
    }

    private async Task<Result<MobileNumberQueryRecord, VerificationFlowFailure>> GetMobileNumberAsync(
        EcliptixSchemaContext schemeContext,
        GetMobileNumberActorEvent cmd,
        CancellationToken cancellationToken)
    {
        try
        {
            Option<MobileNumberEntity> mobileOpt =
                await MobileNumberQueries.GetByUniqueId(schemeContext, cmd.MobileNumberIdentifier, cancellationToken);
            if (!mobileOpt.HasValue)
            {
                return Result<MobileNumberQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound(VerificationFlowMessageKeys.MobileNotFound));
            }

            MobileNumberEntity mobile = mobileOpt.Value!;
            return Result<MobileNumberQueryRecord, VerificationFlowFailure>.Ok(new MobileNumberQueryRecord
            {
                MobileNumber = mobile.Number,
                Region = mobile.Region,
                UniqueId = mobile.UniqueId
            });
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[GetMobileNumber] Operation failed for mobile: {MobileId}", cmd.MobileNumberIdentifier);
            return Result<MobileNumberQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.FromMobileNumber(MobileNumberFailure.GetFailed(ex)));
        }
    }

    private async Task<Result<Unit, VerificationFlowFailure>> UpdateVerificationFlowStatusAsync(
        EcliptixSchemaContext schemeContext,
        UpdateVerificationFlowStatusActorEvent cmd,
        CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await schemeContext.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            VerificationFlowEntity? flow = await schemeContext.VerificationFlows
                .Where(f => f.UniqueId == cmd.FlowIdentifier && !f.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken);

            if (flow == null)
            {
                Log.Warning("[UpdateFlowStatus] Flow not found: {FlowId}", cmd.FlowIdentifier);
                await transaction.RollbackAsync();
                return Result<Unit, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.FlowNotFound());
            }

            VerificationFlowStatus newStatus = cmd.Status;
            VerificationPurpose purpose = flow.Purpose;

            int rowsAffected = await schemeContext.VerificationFlows
                .Where(f => f.UniqueId == cmd.FlowIdentifier && !f.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                        .SetProperty(f => f.Status, newStatus)
                        .SetProperty(f => f.UpdatedAt, DateTimeOffset.UtcNow),
                    cancellationToken);

            if (rowsAffected == 0)
            {
                Log.Warning("[UpdateFlowStatus] Flow not found (no rows affected): {FlowId}", cmd.FlowIdentifier);
                await transaction.RollbackAsync();
                return Result<Unit, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.FlowNotFound());
            }

            await transaction.CommitAsync(cancellationToken);

            if (purpose == VerificationPurpose.PasswordRecovery && newStatus == VerificationFlowStatus.Verified && _membershipPersistorActor != null)
            {
                Log.Information(
                    "[UPDATE-FLOW-STATUS] Password recovery flow {FlowId} marked as verified. Sending async request to update membership VerificationFlowId",
                    cmd.FlowIdentifier);

                UpdateMembershipVerificationFlowEvent updateMembershipEvent = new(
                    cmd.FlowIdentifier,
                    purpose,
                    newStatus,
                    cancellationToken);

                _membershipPersistorActor.Tell(updateMembershipEvent);

                Log.Information("[UPDATE-FLOW-STATUS] Membership update request sent for flow {FlowId}",
                    cmd.FlowIdentifier);
            }

            return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[UpdateFlowStatus] Operation failed for flow: {FlowId}", cmd.FlowIdentifier);
            await transaction.RollbackAsync();
            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.UpdateFlowStatusFailed(ex));
        }
    }

    private static async Task<Result<ExistingMembershipResult, VerificationFlowFailure>> CheckExistingMembershipAsync(
        EcliptixSchemaContext schemeContext,
        CheckExistingMembershipActorEvent cmd,
        CancellationToken cancellationToken)
    {
        try
        {
            Option<MembershipEntity> membershipOpt =
                await MembershipQueries.GetByMobileUniqueId(schemeContext, cmd.MobileNumberId, cancellationToken);

            if (!membershipOpt.HasValue)
            {
                return Result<ExistingMembershipResult, VerificationFlowFailure>.Ok(
                    new ExistingMembershipResult { MembershipExists = false });
            }

            MembershipEntity membership = membershipOpt.Value!;

            ProtoMembership.Types.CreationStatus creationStatus = membership.CreationStatus switch
            {
                MembershipCreationStatus.OtpVerified => ProtoMembership.Types.CreationStatus.OtpVerified,
                MembershipCreationStatus.SecureKeySet => ProtoMembership.Types.CreationStatus.SecureKeySet,
                MembershipCreationStatus.PassphraseSet => ProtoMembership.Types.CreationStatus.PassphraseSet,
                null => ProtoMembership.Types.CreationStatus.OtpVerified,
                _ => ProtoMembership.Types.CreationStatus.OtpVerified
            };

            ProtoMembership.Types.ActivityStatus activityStatus = membership.Status switch
            {
                MembershipStatus.Inactive => ProtoMembership.Types.ActivityStatus.Inactive,
                MembershipStatus.Active => ProtoMembership.Types.ActivityStatus.Active,
                _ => ProtoMembership.Types.ActivityStatus.Active
            };

            Option<AccountEntity> accountOpt =
                await AccountQueries.GetDefaultAccountByMembershipId(schemeContext, membership.UniqueId);

            ProtoMembership existingMembership = new()
            {
                UniqueIdentifier = Helpers.GuidToByteString(membership.UniqueId),
                Status = activityStatus,
                CreationStatus = creationStatus,
                AccountUniqueIdentifier = accountOpt.HasValue
                    ? Helpers.GuidToByteString(accountOpt.Value.UniqueId)
                    : ByteString.Empty
            };

            return Result<ExistingMembershipResult, VerificationFlowFailure>.Ok(
                new ExistingMembershipResult { MembershipExists = true, Membership = existingMembership });
        }
        catch (Exception ex)
        {
            bool isTimeout = ex is TimeoutException ||
                           ex is System.Threading.ThreadAbortException ||
                           (ex is TaskCanceledException tce && tce.CancellationToken.IsCancellationRequested);

            Log.Error(ex,
                "[CHECK-EXISTING-MEMBERSHIP] Operation failed. MobileNumberId={MobileNumberId}, " +
                "IsTimeout={IsTimeout}, ExceptionType={ExceptionType}",
                cmd.MobileNumberId,
                isTimeout,
                ex.GetType().Name);

            return Result<ExistingMembershipResult, VerificationFlowFailure>.Err(
                VerificationFlowFailure.FromMembership(MembershipFailure.QueryFailed(ex)));
        }
    }

    private async Task<Result<MobileNumberAvailabilityResponse, VerificationFlowFailure>>
        CheckMobileNumberAvailabilityAsync(
            EcliptixSchemaContext schemeContext,
            CheckMobileNumberAvailabilityActorEvent cmd,
            CancellationToken cancellationToken)
    {
        try
        {
            bool mobileNumberExists = await schemeContext.MobileNumbers
                .AnyAsync(mn => mn.UniqueId == cmd.MobileNumberId && !mn.IsDeleted, cancellationToken);

            if (!mobileNumberExists)
            {
                return Result<MobileNumberAvailabilityResponse, VerificationFlowFailure>.Ok(
                    new MobileNumberAvailabilityResponse
                    {
                        Status = MobileAvailabilityStatus.Available,
                        CanRegister = true,
                        CanContinue = false,
                        LocalizationKey = VerificationFlowMessageKeys.MobileAvailableForRegistration
                    });
            }

            var membershipInfo = await schemeContext.Memberships
                .Where(m => m.MobileNumberId == cmd.MobileNumberId &&
                            !m.IsDeleted &&
                            !m.MobileNumber.IsDeleted)
                .Select(m => new
                {
                    MembershipId = m.UniqueId,
                    Status = m.Status,
                    CreationStatus = m.CreationStatus,
                    DeviceId = m.AppDeviceId,
                    CreatedAt = m.CreatedAt,
                    HasDefaultAccount = m.Accounts.Any(a => a.IsDefaultAccount && !a.IsDeleted),
                    AccountUniqueId = m.Accounts
                        .Where(a => a.IsDefaultAccount && !a.IsDeleted)
                        .Select(a => (Guid?)a.UniqueId)
                        .FirstOrDefault(),
                    HasValidCredentials = m.Accounts
                        .Where(a => a.IsDefaultAccount && !a.IsDeleted)
                        .SelectMany(a => a.SecureKeyAuths)
                        .Any(auth => auth.IsPrimary && auth.IsEnabled && !auth.IsDeleted)
                })
                .AsNoTracking()
                .FirstOrDefaultAsync(cancellationToken);

            if (membershipInfo == null)
            {
                return Result<MobileNumberAvailabilityResponse, VerificationFlowFailure>.Ok(
                    new MobileNumberAvailabilityResponse
                    {
                        Status = MobileAvailabilityStatus.Available,
                        CanRegister = true,
                        CanContinue = false,
                        LocalizationKey = VerificationFlowMessageKeys.MobileAvailableForRegistration
                    });
            }

            Membership.Types.CreationStatus creationStatus = membershipInfo.CreationStatus switch
            {
                MembershipCreationStatus.OtpVerified => Membership.Types.CreationStatus.OtpVerified,
                MembershipCreationStatus.SecureKeySet => Membership.Types.CreationStatus.SecureKeySet,
                MembershipCreationStatus.PassphraseSet => Membership.Types.CreationStatus.PassphraseSet,
                null => Membership.Types.CreationStatus.OtpVerified,
                _ => Membership.Types.CreationStatus.OtpVerified
            };
            Membership.Types.ActivityStatus activityStatus = membershipInfo.Status switch
            {
                MembershipStatus.Inactive => Membership.Types.ActivityStatus.Inactive,
                MembershipStatus.Active => Membership.Types.ActivityStatus.Active,
                _ => Membership.Types.ActivityStatus.Active
            };

            if (creationStatus == Membership.Types.CreationStatus.OtpVerified &&
                membershipInfo.HasValidCredentials)
            {
                Log.Warning(
                    "[CHECK-AVAILABILITY-INCONSISTENCY] Status={Status} but credentials exist. " +
                    "MembershipId={MembershipId}, DeviceId={DeviceId}. " +
                    "Treating as complete registration (SecureKeySet). Migration will fix status in DB.",
                    creationStatus, membershipInfo.MembershipId, membershipInfo.DeviceId);

                creationStatus = Membership.Types.CreationStatus.SecureKeySet;
            }

            if (membershipInfo.HasDefaultAccount &&
                !membershipInfo.HasValidCredentials &&
                creationStatus != Membership.Types.CreationStatus.OtpVerified)
            {
                Log.Warning(
                    "[CHECK-AVAILABILITY] Data corruption: Account exists without credentials. MembershipId={MembershipId}, DeviceId={DeviceId}, CreationStatus={CreationStatus}",
                    membershipInfo.MembershipId, cmd.DeviceId, creationStatus);

                return Result<MobileNumberAvailabilityResponse, VerificationFlowFailure>.Ok(
                    new MobileNumberAvailabilityResponse
                    {
                        Status = MobileAvailabilityStatus.DataCorruption,
                        CanRegister = false,
                        CanContinue = false,
                        ExistingMembershipId = Helpers.GuidToByteString(membershipInfo.MembershipId),
                        RegisteredDeviceId = Helpers.GuidToByteString(membershipInfo.DeviceId),
                        CreationStatus = creationStatus,
                        ActivityStatus = activityStatus,
                        LocalizationKey = VerificationFlowMessageKeys.MobileDataCorruption
                    });
            }

            if (creationStatus is Membership.Types.CreationStatus.OtpVerified
                    or Membership.Types.CreationStatus.PassphraseSet &&
                !membershipInfo.HasValidCredentials)
            {
                DateTimeOffset now = DateTimeOffset.UtcNow;
                TimeSpan timeSinceCreation = now - membershipInfo.CreatedAt;
                TimeSpan completionWindow = _securityConfig.CurrentValue.MembershipPersistor.MembershipCreationWindow;

                if (timeSinceCreation > completionWindow)
                {
                    Log.Warning(
                        "[CHECK-AVAILABILITY] Registration window expired. MembershipId={MembershipId}, " +
                        "CreatedAt={CreatedAt}, WindowHours={WindowHours}, ElapsedHours={ElapsedHours}",
                        membershipInfo.MembershipId,
                        membershipInfo.CreatedAt,
                        completionWindow.TotalHours,
                        timeSinceCreation.TotalHours);

                    return Result<MobileNumberAvailabilityResponse, VerificationFlowFailure>.Ok(
                        new MobileNumberAvailabilityResponse
                        {
                            Status = MobileAvailabilityStatus.RegistrationExpired,
                            CanRegister = true,
                            CanContinue = false,
                            LocalizationKey = VerificationFlowMessageKeys.MobileRegistrationExpired
                        });
                }

                if (membershipInfo.DeviceId != cmd.DeviceId)
                {
                    Log.Warning(
                        "[CHECK-AVAILABILITY] Cross-device registration blocked. MembershipId: {MembershipId}, " +
                        "RegisteredDevice: {RegisteredDevice}, RequestingDevice: {RequestingDevice}",
                        membershipInfo.MembershipId, membershipInfo.DeviceId, cmd.DeviceId);

                    return Result<MobileNumberAvailabilityResponse, VerificationFlowFailure>.Ok(
                        new MobileNumberAvailabilityResponse
                        {
                            Status = MobileAvailabilityStatus.IncompleteRegistration,
                            CanRegister = false,
                            CanContinue = false,
                            ExistingMembershipId = Helpers.GuidToByteString(membershipInfo.MembershipId),
                            RegisteredDeviceId = Helpers.GuidToByteString(membershipInfo.DeviceId),
                            CreationStatus = creationStatus,
                            ActivityStatus = activityStatus,
                            LocalizationKey = VerificationFlowMessageKeys.MobileIncompleteRegistrationDifferentDevice
                        });
                }

                MobileNumberAvailabilityResponse response = new()
                {
                    Status = MobileAvailabilityStatus.IncompleteRegistration,
                    CanRegister = false,
                    CanContinue = true,
                    ExistingMembershipId = Helpers.GuidToByteString(membershipInfo.MembershipId),
                    RegisteredDeviceId = Helpers.GuidToByteString(membershipInfo.DeviceId),
                    CreationStatus = creationStatus,
                    ActivityStatus = activityStatus,
                    LocalizationKey = VerificationFlowMessageKeys.MobileIncompleteRegistration
                };

                if (membershipInfo.AccountUniqueId.HasValue)
                {
                    ByteString accountId = Helpers.GuidToByteString(membershipInfo.AccountUniqueId.Value);
                    response.AccountUniqueIdentifier = accountId;
                }

                return Result<MobileNumberAvailabilityResponse, VerificationFlowFailure>.Ok(response);
            }

            if (membershipInfo.HasValidCredentials)
            {
                Membership.Types.ActivityStatus membershipActivityStatus = membershipInfo.Status switch
                {
                    MembershipStatus.Inactive => Membership.Types.ActivityStatus.Inactive,
                    MembershipStatus.Active => Membership.Types.ActivityStatus.Active,
                    _ => Membership.Types.ActivityStatus.Active
                };
                bool isActive = membershipActivityStatus == Membership.Types.ActivityStatus.Active;
                MobileAvailabilityStatus status = isActive
                    ? MobileAvailabilityStatus.TakenActive
                    : MobileAvailabilityStatus.TakenInactive;
                string localizationKey = isActive
                    ? VerificationFlowMessageKeys.MobileTakenActiveAccount
                    : VerificationFlowMessageKeys.MobileTakenInactiveAccount;

                return Result<MobileNumberAvailabilityResponse, VerificationFlowFailure>.Ok(
                    new MobileNumberAvailabilityResponse
                    {
                        Status = status,
                        CanRegister = false,
                        CanContinue = false,
                        RegisteredDeviceId = Helpers.GuidToByteString(membershipInfo.DeviceId),
                        CreationStatus = creationStatus,
                        ActivityStatus = activityStatus,
                        LocalizationKey = localizationKey
                    });
            }

            Log.Warning(
                "[CHECK-AVAILABILITY] Unexpected state. MembershipId={MembershipId}, CreationStatus={CreationStatus}, HasAccount={HasAccount}, HasCredentials={HasCredentials}",
                membershipInfo.MembershipId, creationStatus, membershipInfo.HasDefaultAccount,
                membershipInfo.HasValidCredentials);

            return Result<MobileNumberAvailabilityResponse, VerificationFlowFailure>.Ok(
                new MobileNumberAvailabilityResponse
                {
                    Status = MobileAvailabilityStatus.Available,
                    CanRegister = true,
                    CanContinue = false,
                    LocalizationKey = VerificationFlowMessageKeys.MobileAvailableForRegistration
                });
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "[CHECK-AVAILABILITY] Exception checking availability. MobileNumberId={MobileNumberId}, DeviceId={DeviceId}",
                cmd.MobileNumberId, cmd.DeviceId);

            return Result<MobileNumberAvailabilityResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.CheckMobileAvailabilityFailed(ex));
        }
    }

    private async Task<Result<CreateOtpResult, VerificationFlowFailure>> CreateOtpAsync(
        EcliptixSchemaContext schemeContext,
        CreateOtpActorEvent cmd,
        CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await schemeContext.Database.BeginTransactionAsync(cancellationToken);

        try
        {
            Option<VerificationFlowEntity> flowOpt =
                await VerificationFlowQueries.GetByUniqueId(schemeContext, cmd.OtpRecord.FlowUniqueId,
                    cancellationToken);
            if (!flowOpt.HasValue || flowOpt.Value!.ExpiresAt <= DateTimeOffset.UtcNow)
            {
                await transaction.RollbackAsync();
                return Result<CreateOtpResult, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.FlowNotFoundOrInvalid());
            }

            VerificationFlowEntity flow = flowOpt.Value!;

            VerificationFlowPersistorSettings
                persistorSettings = _securityConfig.CurrentValue.VerificationFlowPersistor;
            DateTimeOffset rateLimitLookback = DateTimeOffset.UtcNow - persistorSettings.RateLimitLookback;
            (int mobileOtpCount, DateTimeOffset? lastFlowUpdate) =
                await VerificationFlowQueries.CountRecentOtpsByMobileWithLastUpdate(
                    schemeContext, flow.MobileNumberId, rateLimitLookback, cancellationToken);

            int maxOtpsPerMobile = _securityConfig.CurrentValue.VerificationFlowLimits.MaxOtpSendsPerMobilePerHour;

            if (mobileOtpCount >= maxOtpsPerMobile)
            {
                if (lastFlowUpdate.HasValue)
                {
                    int cooldownMinutes =
                        _securityConfig.CurrentValue.VerificationFlowLimits.OtpExhaustionCooldownMinutes;
                    DateTimeOffset cooldownEndsAt = lastFlowUpdate.Value.AddMinutes(cooldownMinutes);
                    DateTimeOffset currentTime = DateTimeOffset.UtcNow;

                    if (currentTime < cooldownEndsAt)
                    {
                        uint remainingMinutes = (uint)Math.Ceiling((cooldownEndsAt - currentTime).TotalMinutes);
                        await transaction.RollbackAsync();
                        return Result<CreateOtpResult, VerificationFlowFailure>.Err(
                            VerificationFlowFailure.RateLimitExceeded(remainingMinutes.ToString()));
                    }
                }
            }

            if (flow.OtpCount >= _securityConfig.CurrentValue.VerificationFlowLimits.MaxOtpSendsPerFlow)
            {
                await transaction.RollbackAsync();
                return Result<CreateOtpResult, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.FromOtp(OtpFailure.MaxAttemptsReached()));
            }

            Guid requestedOtpId = cmd.OtpRecord.UniqueIdentifier != Guid.Empty
                ? cmd.OtpRecord.UniqueIdentifier
                : Guid.NewGuid();

            if (cmd.OtpRecord.UniqueIdentifier != Guid.Empty)
            {
                bool otpAlreadyExists = await schemeContext.OtpCodes
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

            await schemeContext.OtpCodes
                .Where(o => o.VerificationFlowId == flow.Id && o.Status == OtpStatus.Active && !o.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                        .SetProperty(o => o.Status, OtpStatus.Expired)
                        .SetProperty(o => o.UpdatedAt, DateTimeOffset.UtcNow),
                    cancellationToken);

            OtpCodeEntity otp = new()
            {
                UniqueId = requestedOtpId,
                VerificationFlowId = flow.Id,
                OtpValue = cmd.OtpRecord.OtpHash,
                OtpSalt = cmd.OtpRecord.OtpSalt,
                Status = cmd.OtpRecord.Status,
                ExpiresAt = cmd.OtpRecord.ExpiresAt,
                AttemptCount = 0,
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow,
                IsDeleted = false
            };

            schemeContext.OtpCodes.Add(otp);

            DateTimeOffset now = DateTimeOffset.UtcNow;
            await schemeContext.VerificationFlows
                .Where(f => f.Id == flow.Id)
                .ExecuteUpdateAsync(setters => setters
                        .SetProperty(f => f.OtpCount, f => f.OtpCount + 1)
                        .SetProperty(f => f.LastOtpSentAt, now)
                        .SetProperty(f => f.ResendAvailableAt, (DateTimeOffset?)null)
                        .SetProperty(f => f.UpdatedAt, now),
                    cancellationToken);

            await schemeContext.SaveChangesAsync(cancellationToken);

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
                VerificationFlowFailure.CreateOtpFailed(ex));
        }
    }

    private async Task<Result<Guid, VerificationFlowFailure>> EnsureMobileNumberAsync(
        EcliptixSchemaContext schemeContext,
        EnsureMobileNumberActorEvent cmd,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(cmd.MobileNumber))
        {
            return Result<Guid, VerificationFlowFailure>.Err(
                VerificationFlowFailure.MobileNumberInvalid());
        }

        await using IDbContextTransaction transaction =
            await schemeContext.Database.BeginTransactionAsync(cancellationToken);

        try
        {
            Option<MobileNumberEntity> existingOpt = await MobileNumberQueries.GetByNumberAndRegion(
                schemeContext, cmd.MobileNumber, cmd.RegionCode, cancellationToken);

            if (existingOpt.HasValue)
            {
                await transaction.CommitAsync(cancellationToken);
                return Result<Guid, VerificationFlowFailure>.Ok(existingOpt.Value!.UniqueId);
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

            schemeContext.MobileNumbers.Add(mobile);
            await schemeContext.SaveChangesAsync(cancellationToken);

            await transaction.CommitAsync(cancellationToken);

            return Result<Guid, VerificationFlowFailure>.Ok(mobile.UniqueId);
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync();
            return Result<Guid, VerificationFlowFailure>.Err(
                VerificationFlowFailure.FromMobileNumber(MobileNumberFailure.EnsureFailed(ex)));
        }
    }

    private static async Task<Result<Guid, VerificationFlowFailure>> VerifyMobileForSecretKeyRecoveryAsync(
        EcliptixSchemaContext schemeContext,
        VerifyMobileForSecretKeyRecoveryActorEvent cmd,
        CancellationToken cancellationToken)
    {
        try
        {
            Option<MobileNumberEntity> mobileOpt = await MobileNumberQueries.GetByNumberAndRegion(
                schemeContext, cmd.MobileNumber, cmd.RegionCode, cancellationToken);

            if (!mobileOpt.HasValue)
            {
                return Result<Guid, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.FromMobileNumber(MobileNumberFailure.NotFound()));
            }

            return Result<Guid, VerificationFlowFailure>.Ok(mobileOpt.Value!.UniqueId);
        }
        catch (Exception ex)
        {
            return Result<Guid, VerificationFlowFailure>.Err(
                VerificationFlowFailure.FromMobileNumber(MobileNumberFailure.GetFailed(ex)));
        }
    }

    private static Result<VerificationFlowQueryRecord, VerificationFlowFailure> MapToVerificationFlowRecord(
        VerificationFlowEntity flow)
    {
        OtpCodeEntity? activeOtp = flow.OtpCodes?.FirstOrDefault(o => o.Status == OtpStatus.Active && !o.IsDeleted);
        Option<OtpQueryRecord> otpActive = activeOtp != null
            ? Option<OtpQueryRecord>.Some(new OtpQueryRecord
            {
                UniqueIdentifier = activeOtp.UniqueId,
                FlowUniqueId = flow.UniqueId,
                MobileNumberIdentifier = flow.MobileNumber?.UniqueId ?? Guid.Empty,
                OtpHash = activeOtp.OtpValue,
                OtpSalt = activeOtp.OtpSalt,
                ExpiresAt = activeOtp.ExpiresAt,
                Status = activeOtp.Status,
                IsActive = activeOtp.Status == OtpStatus.Active
            })
            : Option<OtpQueryRecord>.None;

        VerificationFlowQueryRecord flowRecord = new()
        {
            UniqueIdentifier = flow.UniqueId,
            MobileNumberIdentifier = flow.MobileNumber?.UniqueId ?? Guid.Empty,
            AppDeviceIdentifier = flow.AppDeviceId,
            ConnectId = (uint?)flow.ConnectionId,
            ExpiresAt = flow.ExpiresAt,
            Status = flow.Status,
            Purpose = flow.Purpose,
            OtpCount = flow.OtpCount,
            OtpActive = otpActive.HasValue ? otpActive.Value! : null
        };

        return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Ok(flowRecord);
    }


    private static async Task<Result<Unit, VerificationFlowFailure>> IncrementOtpAttemptCountAsync(
        EcliptixSchemaContext schemeContext,
        IncrementOtpAttemptCountActorEvent cmd,
        CancellationToken cancellationToken)
    {
        try
        {
            int updated = await schemeContext.OtpCodes
                .Where(o => o.UniqueId == cmd.OtpUniqueId && !o.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                        .SetProperty(o => o.AttemptCount, o => (short)(o.AttemptCount + 1))
                        .SetProperty(o => o.UpdatedAt, DateTimeOffset.UtcNow),
                    cancellationToken);

            if (updated == 0)
            {
                return Result<Unit, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.FromOtp(OtpFailure.NotFound()));
            }

            return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.IncrementAttemptCountFailed(ex));
        }
    }

    private static async Task<Result<Unit, VerificationFlowFailure>> LogFailedAttemptAsync(
        EcliptixSchemaContext schemeContext,
        LogFailedOtpAttemptActorEvent cmd,
        CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await schemeContext.Database.BeginTransactionAsync(cancellationToken);

        try
        {
            OtpCodeEntity? otp = await schemeContext.OtpCodes
                .Where(o => o.UniqueId == cmd.OtpUniqueId && !o.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken);

            if (otp == null)
            {
                await transaction.RollbackAsync();
                return Result<Unit, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.FromOtp(OtpFailure.NotFound()));
            }

            FailedOtpAttemptEntity failedAttempt = new()
            {
                OtpRecordId = otp.Id,
                AttemptedValue = "***",
                FailureReason = cmd.FailureReason,
                AttemptedAt = DateTimeOffset.UtcNow,
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow,
                IsDeleted = false
            };

            schemeContext.FailedOtpAttempts.Add(failedAttempt);
            await schemeContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            Log.Information("[OTP-FAILED-ATTEMPT] Logged failed attempt for OTP {OtpId}, Reason: {Reason}",
                cmd.OtpUniqueId, cmd.FailureReason);

            return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync();
            Log.Error(ex, "[OTP-FAILED-ATTEMPT] Error logging failed attempt for OTP {OtpId}", cmd.OtpUniqueId);
            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.LogAttemptFailed(ex));
        }
    }

    private static async Task<Result<short, VerificationFlowFailure>> GetOtpAttemptCountAsync(
        EcliptixSchemaContext schemeContext,
        GetOtpAttemptCountActorEvent cmd,
        CancellationToken cancellationToken)
    {
        try
        {
            var otpData = await schemeContext.OtpCodes
                .Where(o => o.UniqueId == cmd.OtpUniqueId && !o.IsDeleted)
                .Select(o => new { o.AttemptCount })
                .FirstOrDefaultAsync(cancellationToken);

            if (otpData == null)
            {
                return Result<short, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.FromOtp(OtpFailure.NotFound()));
            }

            return Result<short, VerificationFlowFailure>.Ok(otpData.AttemptCount);
        }
        catch (Exception ex)
        {
            return Result<short, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Failed to get attempt count: {ex.Message}", ex));
        }
    }

    protected override VerificationFlowFailure MapDbException(DbException ex)
    {
        if (ex is SqlException sqlEx)
        {
            return sqlEx.Number switch
            {
                2627 or 2601 => VerificationFlowFailure.ConcurrencyConflict(
                    $"Unique constraint violation: {sqlEx.Message}"),
                547 => VerificationFlowFailure.Validation($"Foreign key constraint violation: {sqlEx.Message}"),
                1205 => VerificationFlowFailure.ConcurrencyConflict($"Deadlock detected: {sqlEx.Message}"),
                -2 => VerificationFlowFailure.PersistorAccess("Command timeout occurred", sqlEx),
                2 => VerificationFlowFailure.PersistorAccess("Network error occurred", sqlEx),
                18456 => VerificationFlowFailure.PersistorAccess("Authentication failed", sqlEx),
                _ => VerificationFlowFailure.PersistorAccess($"Database error (Code: {sqlEx.Number}): {sqlEx.Message}",
                    sqlEx)
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
