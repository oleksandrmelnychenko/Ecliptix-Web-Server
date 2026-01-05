using System.Data;
using System.Data.Common;
using Akka.Actor;
using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Account;
using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;
using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.MobileNumber;
using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Otp;
using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.VerificationFlow;
using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.IdentityAccess.Domain.Memberships.Persistors.CompiledQueries;
using Ecliptix.IdentityAccess.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.IdentityAccess.Domain.Memberships.Persistors.QueryResults;
using Ecliptix.IdentityAccess.Domain.Schema;
using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Ecliptix.Protobuf.Membership;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Configuration;
using Google.Protobuf;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Options;
using Serilog;
using MembershipEntity = Ecliptix.IdentityAccess.Domain.Schema.Entities.MembershipEntity;
using ProtoMembership = Ecliptix.Protobuf.Membership.Membership;

namespace Ecliptix.IdentityAccess.Domain.Memberships.Persistors;

public class VerificationFlowPersistorActor : PersistorBase<VerificationFlowFailure>
{
    private readonly Option<IActorRef> _membershipPersistorActor;
    private readonly IOptionsMonitor<SecurityConfiguration> _securityConfig;

    private sealed record MembershipCheckInfo
    {
        public Guid MembershipId { get; init; }
        public MembershipStatus? Status { get; init; }
        public MembershipCreationStatus? CreationStatus { get; init; }
        public Guid DeviceId { get; init; }
        public DateTimeOffset CreatedAt { get; init; }
        public bool HasDefaultAccount { get; init; }
        public Guid? AccountUniqueId { get; init; }
        public bool HasValidCredentials { get; init; }
    }

    public VerificationFlowPersistorActor(
        IDbContextFactory<EcliptixSchemaContext> dbContextFactory,
        IOptionsMonitor<SecurityConfiguration> securityConfig,
        Option<IActorRef> membershipPersistorActor = default)
        : base(dbContextFactory)
    {
        _membershipPersistorActor = membershipPersistorActor;
        _securityConfig = securityConfig;
        Become(Ready);
    }

    public static Props Build(IDbContextFactory<EcliptixSchemaContext> dbContextFactory,
        IOptionsMonitor<SecurityConfiguration> securityConfig, Option<IActorRef> membershipPersistorActor = default)
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

        ReceivePersistorCommand<IncrementOtpAttemptCountActorEvent, short>(
            IncrementOtpAttemptCountAsync,
            "IncrementOtpAttemptCount");

        ReceivePersistorCommand<LogFailedOtpAttemptActorEvent, Unit>(
            LogFailedAttemptAsync,
            "LogFailedAttempt");

        ReceivePersistorCommand<GetOtpAttemptCountActorEvent, short>(
            GetOtpAttemptCountAsync,
            "GetOtpAttemptCount");

        ReceivePersistorCommand<QueryFlowStatusByConnectionIdActorEvent, FlowStatusQueryRecord>(
            QueryFlowStatusByConnectionIdAsync,
            "QueryFlowStatusByConnectionId");
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
            await schemeContext.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);

        try
        {
            VerificationFlowPersistorSettings persistorSettings = _securityConfig.CurrentValue.VerificationFlowPersistor;

            Result<MobileNumberEntity, VerificationFlowFailure> validationResult = await ValidateInputsAsync(schemeContext, cmd, cancellationToken);
            if (validationResult.IsErr)
            {
                await transaction.RollbackAsync();
                return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(validationResult.UnwrapErr());
            }
            MobileNumberEntity mobile = validationResult.Unwrap();

            await HandleLingeringActiveFlowAsync(schemeContext, cmd, cancellationToken);

            VerificationFlowEntity? existingByConnectionId = await schemeContext.VerificationFlows
                .Where(vf => vf.ConnectionId == cmd.ConnectId
                    && vf.Status == VerificationFlowStatus.Pending
                    && !vf.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken);

            if (existingByConnectionId != null)
            {
                DateTimeOffset now = DateTimeOffset.UtcNow;

                await schemeContext.VerificationFlows
                    .Where(vf => vf.Id == existingByConnectionId.Id)
                    .ExecuteUpdateAsync(setters => setters
                        .SetProperty(vf => vf.Status, VerificationFlowStatus.Expired)
                        .SetProperty(vf => vf.ConnectionId, (long?)null)
                        .SetProperty(vf => vf.ExpiresAt, now)
                        .SetProperty(vf => vf.UpdatedAt, now),
                        cancellationToken);

                await schemeContext.OtpCodes
                    .Where(o => o.VerificationFlowId == existingByConnectionId.Id
                        && o.Status == OtpStatus.Active
                        && !o.IsDeleted)
                    .ExecuteUpdateAsync(setters => setters
                        .SetProperty(o => o.Status, OtpStatus.Expired)
                        .SetProperty(o => o.UpdatedAt, now),
                        cancellationToken);

                Log.Debug(
                    "[verification.flow.persistor.connection-id-cleanup] Silently expired flow {FlowId} with ConnectionId {ConnectionId}",
                    existingByConnectionId.UniqueId, cmd.ConnectId);
            }

            if (cmd.Purpose == VerificationPurpose.SecureKeyRecovery)
            {
                Option<VerificationFlowFailure> recoveryRuleResult = await HandlePasswordRecoveryRulesAsync(
                    schemeContext, cmd, mobile.UniqueId, persistorSettings, cancellationToken);

                if (recoveryRuleResult.IsSome)
                {
                    await transaction.RollbackAsync();
                    return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(recoveryRuleResult.Value!);
                }
            }

            Option<VerificationFlowFailure> rateLimitResult = await CheckGeneralRateLimitsAsync(
                schemeContext, cmd, mobile.UniqueId, persistorSettings, cancellationToken);

            if (rateLimitResult.IsSome)
            {
                await transaction.RollbackAsync();
                return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(rateLimitResult.Value!);
            }

            VerificationFlowEntity flow = CreateNewVerificationFlow(cmd, mobile.UniqueId, persistorSettings);
            schemeContext.VerificationFlows.Add(flow);

            await schemeContext.SaveChangesAsync(cancellationToken);
            Log.Information("Successfully saved verification flow. FlowId: {FlowId}", flow.UniqueId);

            await transaction.CommitAsync(cancellationToken);
            Log.Information("Transaction committed successfully for flow {FlowId}", flow.UniqueId);

            return await GetFinalFlowRecordAsync(schemeContext, flow.UniqueId, cancellationToken);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[InitiateFlow] Operation failed. Purpose: {Purpose}", cmd.Purpose);
            await transaction.RollbackAsync();
            return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InitiateFlowFailed(ex));
        }
    }

    private static async Task<Result<VerificationFlowQueryRecord, VerificationFlowFailure>> GetFinalFlowRecordAsync(
        EcliptixSchemaContext schemeContext,
        Guid flowUniqueId,
        CancellationToken cancellationToken)
    {
        Option<VerificationFlowEntity> flowWithOtpOpt =
            await VerificationFlowQueries.GetByUniqueIdWithActiveOtp(schemeContext, flowUniqueId,
                cancellationToken);
        if (!flowWithOtpOpt.IsSome)
        {
            Log.Error("[InitiateFlow] Flow not found after creation: {FlowId}", flowUniqueId);
            return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.FlowNotFoundAfterCreation());
        }

        return MapToVerificationFlowRecord(flowWithOtpOpt.Value!);
    }

    private VerificationFlowEntity CreateNewVerificationFlow(
        InitiateFlowAndReturnStateActorEvent cmd,
        Guid mobileUniqueId,
        VerificationFlowPersistorSettings persistorSettings)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return new()
        {
            UniqueId = Guid.NewGuid(),
            MobileNumberId = mobileUniqueId,
            AppDeviceId = cmd.AppDeviceId,
            Purpose = cmd.Purpose,
            Status = VerificationFlowStatus.Pending,
            ExpiresAt = now + persistorSettings.FlowExpiration,
            ConnectionId = cmd.ConnectId,
            OtpCount = 0,
            CreatedAt = now,
            UpdatedAt = now,
            IsDeleted = false
        };
    }

    private static async Task<Option<VerificationFlowFailure>> CheckGeneralRateLimitsAsync(
        EcliptixSchemaContext schemeContext,
        InitiateFlowAndReturnStateActorEvent cmd,
        Guid mobileUniqueId,
        VerificationFlowPersistorSettings persistorSettings,
        CancellationToken cancellationToken)
    {
        DateTimeOffset rateLimitLookback = DateTimeOffset.UtcNow - persistorSettings.RateLimitLookback;

        int mobileFlowCount = await VerificationFlowQueries.CountRecentByMobileId(
            schemeContext, mobileUniqueId, rateLimitLookback, cancellationToken);
        if (mobileFlowCount >= persistorSettings.MaxFlowsPerHourPerMobile)
        {
            Log.Warning("[InitiateFlow] Mobile rate limit exceeded. Count: {Count}, Max: {Max}, Mobile: {MobileId}",
                mobileFlowCount, persistorSettings.MaxFlowsPerHourPerMobile, mobileUniqueId);
            return Option<VerificationFlowFailure>.Some(VerificationFlowFailure.RateLimitExceeded());
        }

        int deviceFlowCount = await VerificationFlowQueries.CountRecentByDevice(
            schemeContext, cmd.AppDeviceId, rateLimitLookback, cancellationToken);
        if (deviceFlowCount >= persistorSettings.MaxFlowsPerHourPerDevice)
        {
            Log.Warning("[InitiateFlow] Device rate limit exceeded. Count: {Count}, Max: {Max}, Device: {DeviceId}",
                deviceFlowCount, persistorSettings.MaxFlowsPerHourPerDevice, cmd.AppDeviceId);
            return Option<VerificationFlowFailure>.Some(VerificationFlowFailure.DeviceRateLimitExceeded());
        }

        return Option<VerificationFlowFailure>.None;
    }

    private static async Task<Result<MobileNumberEntity, VerificationFlowFailure>> ValidateInputsAsync(
        EcliptixSchemaContext schemeContext,
        InitiateFlowAndReturnStateActorEvent cmd,
        CancellationToken cancellationToken)
    {
        Option<MobileNumberEntity> mobileOpt =
            await MobileNumberQueries.GetByUniqueId(schemeContext, cmd.MobileNumberUniqueId, cancellationToken);
        if (!mobileOpt.IsSome)
        {
            Log.Warning("[InitiateFlow] Mobile number not found: {MobileNumberId}", cmd.MobileNumberUniqueId);
            return Result<MobileNumberEntity, VerificationFlowFailure>.Err(
                VerificationFlowFailure.FromMobileNumber(MobileNumberFailure.NotFound()));
        }

        bool deviceExists = await DeviceQueries.ExistsByDeviceId(schemeContext, cmd.AppDeviceId, cancellationToken);
        if (!deviceExists)
        {
            Log.Warning("[InitiateFlow] Device not found: {DeviceId}", cmd.AppDeviceId);
            return Result<MobileNumberEntity, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Validation("Device not found"));
        }

        return Result<MobileNumberEntity, VerificationFlowFailure>.Ok(mobileOpt.Value!);
    }

    private static async Task HandleLingeringActiveFlowAsync(
        EcliptixSchemaContext schemeContext,
        InitiateFlowAndReturnStateActorEvent cmd,
        CancellationToken cancellationToken)
    {
        Option<VerificationFlowEntity> existingActiveFlowOpt =
            await VerificationFlowQueries.GetActiveFlowForRecovery(
                schemeContext,
                cmd.MobileNumberUniqueId,
                cmd.AppDeviceId,
                cmd.Purpose,
                cancellationToken);

        if (existingActiveFlowOpt.IsSome)
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
    }

    private async Task<Option<VerificationFlowFailure>> HandlePasswordRecoveryRulesAsync(
        EcliptixSchemaContext schemeContext,
        InitiateFlowAndReturnStateActorEvent cmd,
        Guid mobileUniqueId,
        VerificationFlowPersistorSettings persistorSettings,
        CancellationToken cancellationToken)
    {
        Option<VerificationFlowFailure> rateLimitFailure = await CheckPasswordRecoveryRateLimitsAsync(
            schemeContext, cmd, mobileUniqueId, persistorSettings, cancellationToken);

        if (rateLimitFailure.IsSome)
        {
            return rateLimitFailure;
        }

        await ExpireOldPasswordRecoveryFlowsAsync(schemeContext, mobileUniqueId, cancellationToken);

        return Option<VerificationFlowFailure>.None;
    }

    private static async Task ExpireOldPasswordRecoveryFlowsAsync(
        EcliptixSchemaContext schemeContext,
        Guid mobileUniqueId,
        CancellationToken cancellationToken)
    {
        List<VerificationFlowEntity> oldActiveFlows = await schemeContext.VerificationFlows
            .Where(vf => vf.MobileNumberId == mobileUniqueId &&
                         vf.Purpose == VerificationPurpose.SecureKeyRecovery &&
                         (vf.Status == VerificationFlowStatus.Pending || vf.Status == VerificationFlowStatus.Verified) &&
                         !vf.IsDeleted)
            .ToListAsync(cancellationToken);

        if (oldActiveFlows.Count > 0)
        {
            Log.Information(
                "[INITIATE-PASSWORD-RECOVERY] Found {Count} old password recovery flows (pending + verified) to expire for mobile ID {MobileId}",
                oldActiveFlows.Count, mobileUniqueId);

            DateTimeOffset now = DateTimeOffset.UtcNow;
            foreach (VerificationFlowEntity oldFlow in oldActiveFlows)
            {
                Log.Information(
                    "[INITIATE-PASSWORD-RECOVERY] Expiring flow {FlowId} with status '{OldStatus}' for mobile ID {MobileId}",
                    oldFlow.UniqueId, oldFlow.Status, mobileUniqueId);

                oldFlow.Status = VerificationFlowStatus.Expired;
                oldFlow.UpdatedAt = now;
            }

            Log.Information(
                "[INITIATE-PASSWORD-RECOVERY] Successfully marked {Count} old password recovery flows for expiration",
                oldActiveFlows.Count);
        }
    }

    private async Task<Option<VerificationFlowFailure>> CheckPasswordRecoveryRateLimitsAsync(
        EcliptixSchemaContext schemeContext,
        InitiateFlowAndReturnStateActorEvent cmd,
        Guid mobileUniqueId,
        VerificationFlowPersistorSettings persistorSettings,
        CancellationToken cancellationToken)
    {
        DateTimeOffset recoveryLookbackTime =
            DateTimeOffset.UtcNow - persistorSettings.PasswordRecoveryLookback;

        int recoveryCountByMobile = await VerificationFlowQueries.CountRecentPasswordRecovery(
            schemeContext, mobileUniqueId, recoveryLookbackTime, cancellationToken);

        int recoveryCountByDevice = await schemeContext.VerificationFlows
            .Where(f => f.AppDeviceId == cmd.AppDeviceId &&
                        f.Purpose == VerificationPurpose.SecureKeyRecovery &&
                        f.CreatedAt >= recoveryLookbackTime &&
                        !f.IsDeleted)
            .AsNoTracking()
            .CountAsync(cancellationToken);

        Log.Information(
            "[INITIATE-PASSWORD-RECOVERY] Recent password recovery counts - Mobile: {MobileCount}, Device: {DeviceCount} for mobile ID {MobileId}",
            recoveryCountByMobile, recoveryCountByDevice, mobileUniqueId);

        int maxAttemptsByMobile = _securityConfig.CurrentValue.VerificationFlowLimits
            .PasswordRecoveryAttemptsPerHourPerMobile;
        int maxAttemptsByDevice = _securityConfig.CurrentValue.VerificationFlowLimits
            .PasswordRecoveryAttemptsPerHourPerDevice;

        if (recoveryCountByMobile >= maxAttemptsByMobile || recoveryCountByDevice >= maxAttemptsByDevice)
        {
            Log.Warning(
                "[InitiateFlow] Password recovery rate limit exceeded. Mobile: {MobileCount}/{MaxMobile}, Device: {DeviceCount}/{MaxDevice}",
                recoveryCountByMobile, maxAttemptsByMobile, recoveryCountByDevice, maxAttemptsByDevice);
            return Option<VerificationFlowFailure>.Some(VerificationFlowFailure.RateLimitExceeded());
        }

        return Option<VerificationFlowFailure>.None;
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
            if (!flowOpt.IsSome)
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
            await schemeContext.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
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

            if (otp.Status == cmd.Status)
            {
                await transaction.CommitAsync(cancellationToken);
                return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
            }

            if (otp.Status is OtpStatus.Used or OtpStatus.Expired)
            {
                await transaction.CommitAsync(cancellationToken);
                return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
            }

            if (otp.Status != OtpStatus.Active)
            {
                await transaction.CommitAsync(cancellationToken);
                return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
            }

            otp.Status = cmd.Status;
            otp.UpdatedAt = utcNow;
            if (cmd.Status == OtpStatus.Used)
            {
                otp.VerifiedAt = utcNow;
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
            if (!mobileOpt.IsSome)
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
            await schemeContext.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
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

            if (purpose == VerificationPurpose.SecureKeyRecovery && newStatus == VerificationFlowStatus.Verified && _membershipPersistorActor.IsSome)
            {
                Log.Information(
                    "[UPDATE-FLOW-STATUS] Password recovery flow {FlowId} marked as verified. Sending async request to update membership VerificationFlowId",
                    cmd.FlowIdentifier);

                UpdateMembershipVerificationFlowEvent updateMembershipEvent = new(
                    cmd.FlowIdentifier,
                    purpose,
                    newStatus,
                    cancellationToken);

                _membershipPersistorActor.Value.Tell(updateMembershipEvent);

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

            if (!membershipOpt.IsSome)
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
                _ => ProtoMembership.Types.CreationStatus.OtpVerified
            };

            ProtoMembership.Types.ActivityStatus activityStatus = membership.Status switch
            {
                MembershipStatus.Inactive => ProtoMembership.Types.ActivityStatus.Inactive,
                _ => ProtoMembership.Types.ActivityStatus.Active
            };

            Option<AccountEntity> accountOpt =
                await AccountQueries.GetDefaultAccountByMembershipId(schemeContext, membership.UniqueId);

            ProtoMembership existingMembership = new()
            {
                UniqueIdentifier = Helpers.GuidToByteString(membership.UniqueId),
                Status = activityStatus,
                CreationStatus = creationStatus,
                AccountUniqueIdentifier = accountOpt.IsSome
                    ? Helpers.GuidToByteString(accountOpt.Value!.UniqueId)
                    : ByteString.Empty
            };

            return Result<ExistingMembershipResult, VerificationFlowFailure>.Ok(
                new ExistingMembershipResult { MembershipExists = true, Membership = existingMembership });
        }
        catch (Exception ex)
        {
            bool isTimeout = ex is TimeoutException ||
                           ex is ThreadAbortException ||
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
                    BuildAvailableResponse());
            }

            MembershipCheckInfo? membershipInfo = await schemeContext.Memberships
                .Where(m => m.MobileNumberId == cmd.MobileNumberId &&
                            !m.IsDeleted &&
                            !m.MobileNumber.IsDeleted)
                .Select(m => new MembershipCheckInfo
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
                    BuildAvailableResponse());
            }

            MobileNumberAvailabilityResponse response = HandleExistingMembership(membershipInfo, cmd.DeviceId);

            return Result<MobileNumberAvailabilityResponse, VerificationFlowFailure>.Ok(response);
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

    private MobileNumberAvailabilityResponse HandleExistingMembership(
        MembershipCheckInfo info, Guid requestingDeviceId)
    {
        (Membership.Types.CreationStatus creationStatus, Membership.Types.ActivityStatus activityStatus) = GetCorrectedMembershipStatus(info);

        Option<MobileNumberAvailabilityResponse> corruptionResponse = CheckForDataCorruption(info, creationStatus, activityStatus, requestingDeviceId);
        if (corruptionResponse.IsSome)
        {
            return corruptionResponse.Value!;
        }

        if (creationStatus is Membership.Types.CreationStatus.OtpVerified
                or Membership.Types.CreationStatus.PassphraseSet &&
            !info.HasValidCredentials)
        {
            return HandleIncompleteRegistration(info, creationStatus, activityStatus, requestingDeviceId);
        }

        if (info.HasValidCredentials)
        {
            return HandleTakenRegistration(info, creationStatus, activityStatus);
        }

        Log.Warning(
            "[CHECK-AVAILABILITY] Unexpected state. MembershipId={MembershipId}, CreationStatus={CreationStatus}, HasAccount={HasAccount}, HasCredentials={HasCredentials}",
            info.MembershipId, creationStatus, info.HasDefaultAccount, info.HasValidCredentials);

        return BuildAvailableResponse();
    }

    private MobileNumberAvailabilityResponse HandleIncompleteRegistration(
        MembershipCheckInfo info,
        Membership.Types.CreationStatus creationStatus,
        Membership.Types.ActivityStatus activityStatus,
        Guid requestingDeviceId)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        TimeSpan timeSinceCreation = now - info.CreatedAt;
        TimeSpan completionWindow = _securityConfig.CurrentValue.MembershipPersistor.MembershipCreationWindow;

        if (timeSinceCreation > completionWindow)
        {
            Log.Warning(
                "[CHECK-AVAILABILITY] Registration window expired. MembershipId={MembershipId}, " +
                "CreatedAt={CreatedAt}, WindowHours={WindowHours}, ElapsedHours={ElapsedHours}",
                info.MembershipId, info.CreatedAt, completionWindow.TotalHours, timeSinceCreation.TotalHours);

            return new MobileNumberAvailabilityResponse
            {
                Status = MobileAvailabilityStatus.RegistrationExpired,
                CanRegister = true,
                CanContinue = false,
                LocalizationKey = VerificationFlowMessageKeys.MobileRegistrationExpired
            };
        }

        if (info.DeviceId != requestingDeviceId)
        {
            Log.Warning(
                "[CHECK-AVAILABILITY] Cross-device registration blocked. MembershipId: {MembershipId}, " +
                "RegisteredDevice: {RegisteredDevice}, RequestingDevice: {RequestingDevice}",
                info.MembershipId, info.DeviceId, requestingDeviceId);

            return new MobileNumberAvailabilityResponse
            {
                Status = MobileAvailabilityStatus.IncompleteRegistration,
                CanRegister = false,
                CanContinue = false,
                ExistingMembershipId = Helpers.GuidToByteString(info.MembershipId),
                RegisteredDeviceId = Helpers.GuidToByteString(info.DeviceId),
                CreationStatus = creationStatus,
                ActivityStatus = activityStatus,
                LocalizationKey = VerificationFlowMessageKeys.MobileIncompleteRegistrationDifferentDevice
            };
        }

        MobileNumberAvailabilityResponse response = new()
        {
            Status = MobileAvailabilityStatus.IncompleteRegistration,
            CanRegister = false,
            CanContinue = true,
            ExistingMembershipId = Helpers.GuidToByteString(info.MembershipId),
            RegisteredDeviceId = Helpers.GuidToByteString(info.DeviceId),
            CreationStatus = creationStatus,
            ActivityStatus = activityStatus,
            LocalizationKey = VerificationFlowMessageKeys.MobileIncompleteRegistration
        };

        if (info.AccountUniqueId.HasValue)
        {
            response.AccountUniqueIdentifier = Helpers.GuidToByteString(info.AccountUniqueId.Value);
        }

        return response;
    }

    private static Option<MobileNumberAvailabilityResponse> CheckForDataCorruption(
        MembershipCheckInfo info,
        Membership.Types.CreationStatus creationStatus,
        Membership.Types.ActivityStatus activityStatus,
        Guid requestingDeviceId)
    {
        if (info.HasDefaultAccount &&
            !info.HasValidCredentials &&
            creationStatus != Membership.Types.CreationStatus.OtpVerified)
        {
            Log.Warning(
                "[CHECK-AVAILABILITY] Data corruption: Account exists without credentials. MembershipId={MembershipId}, DeviceId={DeviceId}, CreationStatus={CreationStatus}",
                info.MembershipId, requestingDeviceId, creationStatus);

            return Option<MobileNumberAvailabilityResponse>.Some(
                new MobileNumberAvailabilityResponse
                {
                    Status = MobileAvailabilityStatus.DataCorruption,
                    CanRegister = false,
                    CanContinue = false,
                    ExistingMembershipId = Helpers.GuidToByteString(info.MembershipId),
                    RegisteredDeviceId = Helpers.GuidToByteString(info.DeviceId),
                    CreationStatus = creationStatus,
                    ActivityStatus = activityStatus,
                    LocalizationKey = VerificationFlowMessageKeys.MobileDataCorruption
                });
        }

        return Option<MobileNumberAvailabilityResponse>.None;
    }

    private static MobileNumberAvailabilityResponse HandleTakenRegistration(
        MembershipCheckInfo info,
        Membership.Types.CreationStatus creationStatus,
        Membership.Types.ActivityStatus activityStatus)
    {
        bool isActive = activityStatus == Membership.Types.ActivityStatus.Active;
        MobileAvailabilityStatus status = isActive
            ? MobileAvailabilityStatus.TakenActive
            : MobileAvailabilityStatus.TakenInactive;
        string localizationKey = isActive
            ? VerificationFlowMessageKeys.MobileTakenActiveAccount
            : VerificationFlowMessageKeys.MobileTakenInactiveAccount;

        return new MobileNumberAvailabilityResponse
        {
            Status = status,
            CanRegister = false,
            CanContinue = false,
            RegisteredDeviceId = Helpers.GuidToByteString(info.DeviceId),
            CreationStatus = creationStatus,
            ActivityStatus = activityStatus,
            LocalizationKey = localizationKey
        };
    }

    private static (Membership.Types.CreationStatus Creation, Membership.Types.ActivityStatus Activity)
        GetCorrectedMembershipStatus(MembershipCheckInfo info)
    {
        Membership.Types.CreationStatus creationStatus = info.CreationStatus switch
        {
            MembershipCreationStatus.OtpVerified => Membership.Types.CreationStatus.OtpVerified,
            MembershipCreationStatus.SecureKeySet => Membership.Types.CreationStatus.SecureKeySet,
            MembershipCreationStatus.PassphraseSet => Membership.Types.CreationStatus.PassphraseSet,
            _ => Membership.Types.CreationStatus.OtpVerified
        };

        Membership.Types.ActivityStatus activityStatus = info.Status switch
        {
            MembershipStatus.Inactive => Membership.Types.ActivityStatus.Inactive,
            _ => Membership.Types.ActivityStatus.Active
        };

        if (creationStatus == Membership.Types.CreationStatus.OtpVerified &&
            info.HasValidCredentials)
        {
            creationStatus = Membership.Types.CreationStatus.SecureKeySet;
        }

        return (creationStatus, activityStatus);
    }

    private static MobileNumberAvailabilityResponse BuildAvailableResponse()
    {
        return new MobileNumberAvailabilityResponse
        {
            Status = MobileAvailabilityStatus.Available,
            CanRegister = true,
            CanContinue = false,
            LocalizationKey = VerificationFlowMessageKeys.MobileAvailableForRegistration
        };
    }

    private async Task<Result<CreateOtpResult, VerificationFlowFailure>> CreateOtpAsync(
        EcliptixSchemaContext schemeContext,
        CreateOtpActorEvent cmd,
        CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await schemeContext.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);

        try
        {
            Option<VerificationFlowEntity> flowOpt =
                await VerificationFlowQueries.GetByUniqueId(schemeContext, cmd.OtpRecord.FlowUniqueId,
                    cancellationToken);
            if (!flowOpt.IsSome || flowOpt.Value!.ExpiresAt <= DateTimeOffset.UtcNow)
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

            if (mobileOtpCount >= maxOtpsPerMobile && lastFlowUpdate.HasValue)
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
            int resendCooldownSeconds = _securityConfig.CurrentValue.VerificationFlow.ResendCooldownBufferSeconds;
            DateTimeOffset resendAvailableAt = now.AddSeconds(resendCooldownSeconds);

            await schemeContext.VerificationFlows
                .Where(f => f.Id == flow.Id)
                .ExecuteUpdateAsync(setters => setters
                        .SetProperty(f => f.OtpCount, f => f.OtpCount + 1)
                        .SetProperty(f => f.LastOtpSentAt, now)
                        .SetProperty(f => f.ResendAvailableAt, resendAvailableAt)
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
            await schemeContext.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);

        try
        {
            Option<MobileNumberEntity> existingOpt = await MobileNumberQueries.GetByNumberAndRegion(
                schemeContext, cmd.MobileNumber, cmd.RegionCode, cancellationToken);

            if (existingOpt.IsSome)
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

            if (!mobileOpt.IsSome)
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
                IsActive = activeOtp.Status == OtpStatus.Active,
                AttemptCount = activeOtp.AttemptCount
            })
            : Option<OtpQueryRecord>.None;

        VerificationFlowQueryRecord flowRecord = new()
        {
            UniqueIdentifier = flow.UniqueId,
            MobileNumberIdentifier = flow.MobileNumber?.UniqueId ?? Guid.Empty,
            AppDeviceIdentifier = flow.AppDeviceId,
            ConnectId = flow.ConnectionId.HasValue
                ? Option<uint>.Some((uint)flow.ConnectionId.Value)
                : Option<uint>.None,
            ExpiresAt = flow.ExpiresAt,
            Status = flow.Status,
            Purpose = flow.Purpose,
            OtpCount = flow.OtpCount,
            OtpActive = otpActive
        };

        return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Ok(flowRecord);
    }

    private async Task<Result<short, VerificationFlowFailure>> IncrementOtpAttemptCountAsync(
        EcliptixSchemaContext schemeContext,
        IncrementOtpAttemptCountActorEvent cmd,
        CancellationToken cancellationToken)
    {
        try
        {
            short maxAttempts = (short)_securityConfig.CurrentValue.VerificationFlow.MaxOtpVerificationAttempts;

            int updated = await schemeContext.OtpCodes
                .Where(o => o.UniqueId == cmd.OtpUniqueId &&
                            o.Status == OtpStatus.Active &&
                            o.AttemptCount < maxAttempts &&
                            !o.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                        .SetProperty(o => o.AttemptCount, o => (short)(o.AttemptCount + 1))
                        .SetProperty(o => o.UpdatedAt, DateTimeOffset.UtcNow),
                    cancellationToken);

            if (updated == 0)
            {
                short? existingCount = await schemeContext.OtpCodes
                    .Where(o => o.UniqueId == cmd.OtpUniqueId && !o.IsDeleted)
                    .Select(o => (short?)o.AttemptCount)
                    .FirstOrDefaultAsync(cancellationToken);

                if (existingCount == null)
                {
                    return Result<short, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.FromOtp(OtpFailure.NotFound()));
                }

                return Result<short, VerificationFlowFailure>.Ok(existingCount.Value);
            }

            short newCount = await schemeContext.OtpCodes
                .Where(o => o.UniqueId == cmd.OtpUniqueId && !o.IsDeleted)
                .Select(o => o.AttemptCount)
                .FirstAsync(cancellationToken);

            return Result<short, VerificationFlowFailure>.Ok(newCount);
        }
        catch (Exception ex)
        {
            return Result<short, VerificationFlowFailure>.Err(
                VerificationFlowFailure.IncrementAttemptCountFailed(ex));
        }
    }

    private static async Task<Result<Unit, VerificationFlowFailure>> LogFailedAttemptAsync(
        EcliptixSchemaContext schemeContext,
        LogFailedOtpAttemptActorEvent cmd,
        CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await schemeContext.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);

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

    private static async Task<Result<FlowStatusQueryRecord, VerificationFlowFailure>> QueryFlowStatusByConnectionIdAsync(
        EcliptixSchemaContext schemeContext,
        QueryFlowStatusByConnectionIdActorEvent cmd,
        CancellationToken cancellationToken)
    {
        Option<(VerificationFlowStatus Status, DateTimeOffset ExpiresAt)> flowStatusOpt =
            await VerificationFlowQueries.GetFlowStatusByConnectionId(
                schemeContext,
                cmd.ConnectionId,
                cancellationToken);

        if (!flowStatusOpt.IsSome)
        {
            FlowStatusQueryRecord notFoundResult = new(
                IsFound: false,
                Status: VerificationFlowStatus.Pending,
                ExpiresAt: DateTimeOffset.MinValue);

            return Result<FlowStatusQueryRecord, VerificationFlowFailure>.Ok(notFoundResult);
        }

        (VerificationFlowStatus status, DateTimeOffset expiresAt) = flowStatusOpt.Value;

        FlowStatusQueryRecord result = new(
            IsFound: true,
            Status: status,
            ExpiresAt: expiresAt);

        return Result<FlowStatusQueryRecord, VerificationFlowFailure>.Ok(result);
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
