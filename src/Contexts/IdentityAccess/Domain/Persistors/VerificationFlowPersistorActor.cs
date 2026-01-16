using System.Data;
using System.Data.Common;
using Akka.Actor;
using Ecliptix.IdentityAccess.Domain.Memberships;
using Ecliptix.IdentityAccess.Domain.Actors.VerificationFlow;
using Ecliptix.IdentityAccess.Domain.Actors.Membership;
using Ecliptix.IdentityAccess.Domain.Memberships.Otp;
using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.IdentityAccess.Domain.Persistors.CompiledQueries;
using Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;
using Ecliptix.IdentityAccess.Domain.Persistors.QueryResults;
using Ecliptix.IdentityAccess.Domain.Schema;
using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Ecliptix.Protobuf.Membership;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Actors;
using Ecliptix.SharedKernel.Configuration;
using Google.Protobuf;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Options;
using Npgsql;
using Serilog;
using MembershipEntity = Ecliptix.IdentityAccess.Domain.Schema.Entities.MembershipEntity;
using ProtoMembership = Ecliptix.Protobuf.Membership.Membership;
using OtpVerificationPurpose = Ecliptix.IdentityAccess.Domain.Memberships.OtpVerificationPurpose;

namespace Ecliptix.IdentityAccess.Domain.Persistors;

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
        ReceivePersistorCommand<InitiateFlowCommand, VerificationFlowQueryRecord>(
            InitiateFlowAsync,
            PersistorOperation.InitiateVerificationFlow);

        ReceivePersistorCommand<RequestResendOtpCommand, (string Outcome, uint RemainingSeconds)>(
            RequestResendOtpAsync,
            PersistorOperation.RequestResendOtp);

        ReceivePersistorCommand<UpdateVerificationFlowStatusCommand, Unit>(
            UpdateVerificationFlowStatusAsync,
            PersistorOperation.UpdateVerificationFlowStatus);

        ReceivePersistorCommand<ValidateMobileNumberCommand, Guid>(
            EnsureMobileNumberAsync,
            PersistorOperation.EnsureMobileNumber);

        ReceivePersistorCommand<VerifyMobileForSecretKeyRecoveryCommand, Guid>(
            VerifyMobileForSecretKeyRecoveryAsync,
            PersistorOperation.VerifyMobileForSecretKeyRecovery);

        ReceivePersistorCommand<GetMobileNumberQuery, MobileNumberQueryRecord>(
            GetMobileNumberAsync,
            PersistorOperation.GetMobileNumber);

        ReceivePersistorCommand<CreateOtpCommand, CreateOtpResult>(
            CreateOtpAsync,
            PersistorOperation.CreateOtp);

        ReceivePersistorCommand<UpdateOtpStatusCommand, Unit>(
            UpdateOtpStatusAsync,
            PersistorOperation.UpdateOtpStatus);

        ReceivePersistorCommand<ExistsMobileNumberQuery, MobileNumberAvailabilityResponse>(
            CheckMobileNumberAvailabilityAsync,
            PersistorOperation.CheckMobileNumberAvailability);

        ReceivePersistorCommand<ExistsMembershipQuery, ExistingMembershipResult>(
            CheckExistingMembershipAsync,
            PersistorOperation.CheckExistingMembership);

        ReceivePersistorCommand<IncrementOtpAttemptCountCommand, short>(
            IncrementOtpAttemptCountAsync,
            PersistorOperation.IncrementOtpAttemptCount);

        ReceivePersistorCommand<RecordFailedOtpAttemptCommand, Unit>(
            LogFailedAttemptAsync,
            PersistorOperation.LogFailedAttempt);

        ReceivePersistorCommand<GetOtpAttemptCountQuery, short>(
            GetOtpAttemptCountAsync,
            PersistorOperation.GetOtpAttemptCount);

        ReceivePersistorCommand<GetFlowStatusByConnectionIdQuery, FlowStatusQueryRecord>(
            QueryFlowStatusByConnectionIdAsync,
            PersistorOperation.QueryFlowStatusByConnectionId);
    }

    private void ReceivePersistorCommand<TMessage, TResult>(
        Func<EcliptixSchemaContext, TMessage, CancellationToken, Task<Result<TResult, VerificationFlowFailure>>>
            handler,
        PersistorOperation operationName)
        where TMessage : class, ICancellableActorEvent
    {
        Receive<TMessage>(message =>
        {
            IActorRef replyTo = Sender;
            CancellationToken messageToken = message.CancellationToken;

            Task<Result<TResult, VerificationFlowFailure>> Operation(EcliptixSchemaContext schemaContext,
                CancellationToken cancellationToken)
            {
                CancellationToken effectiveToken = CombineCancellationTokens(cancellationToken, messageToken,
                    out CancellationTokenSource? linkedCancellationTokenSource);
                try
                {
                    return handler(schemaContext, message, effectiveToken);
                }
                finally
                {
                    linkedCancellationTokenSource?.Dispose();
                }
            }

            ExecuteWithContext(Operation, operationName, messageToken).PipeTo(replyTo);
        });
    }

    private static CancellationToken CombineCancellationTokens(
        CancellationToken first,
        CancellationToken second,
        out CancellationTokenSource? linkedCancellationTokenSource)
    {
        linkedCancellationTokenSource = null;

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

        linkedCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(first, second);
        return linkedCancellationTokenSource.Token;
    }

    private async Task<Result<VerificationFlowQueryRecord, VerificationFlowFailure>> InitiateFlowAsync(
        EcliptixSchemaContext schemaContext,
        InitiateFlowCommand command,
        CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await schemaContext.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);

        try
        {
            VerificationFlowPersistorSettings persistorSettings = _securityConfig.CurrentValue.VerificationFlowPersistor;

            Result<MobileNumberEntity, VerificationFlowFailure> validationResult = await ValidateInputsAsync(schemaContext, command, cancellationToken);
            if (validationResult.IsErr)
            {
                await transaction.RollbackAsync();
                return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(validationResult.UnwrapErr());
            }
            MobileNumberEntity mobile = validationResult.Unwrap();

            await HandleLingeringActiveFlowAsync(schemaContext, command, cancellationToken);

            VerificationFlowEntity? existingByConnectionId = await schemaContext.VerificationFlows
                .Where(vf => vf.ConnectionId == command.ConnectId
                    && vf.Status == VerificationFlowStatus.Pending
                    && !vf.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken);

            if (existingByConnectionId != null)
            {
                DateTimeOffset now = DateTimeOffset.UtcNow;

                await schemaContext.VerificationFlows
                    .Where(vf => vf.Id == existingByConnectionId.Id)
                    .ExecuteUpdateAsync(setters => setters
                        .SetProperty(vf => vf.Status, VerificationFlowStatus.Expired)
                        .SetProperty(vf => vf.ConnectionId, (long?)null)
                        .SetProperty(vf => vf.ExpiresAt, now)
                        .SetProperty(vf => vf.UpdatedAt, now),
                        cancellationToken);

                await schemaContext.OtpCodes
                    .Where(o => o.VerificationFlowId == existingByConnectionId.Id
                        && o.Status == OtpStatus.Active
                        && !o.IsDeleted)
                    .ExecuteUpdateAsync(setters => setters
                        .SetProperty(o => o.Status, OtpStatus.Expired)
                        .SetProperty(o => o.UpdatedAt, now),
                        cancellationToken);

                Log.Debug(
                    "[verification.flow.persistor.connection-id-cleanup] Silently expired flow {FlowId} with ConnectionId {ConnectionId}",
                    existingByConnectionId.UniqueId, command.ConnectId);
            }

            if (command.Purpose == OtpVerificationPurpose.SecureKeyRecovery)
            {
                Option<VerificationFlowFailure> recoveryRuleResult = await HandlePasswordRecoveryRulesAsync(
                    schemaContext, command, mobile.UniqueId, persistorSettings, cancellationToken);

                if (recoveryRuleResult.IsSome)
                {
                    await transaction.RollbackAsync();
                    return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(recoveryRuleResult.Value!);
                }
            }

            Option<VerificationFlowFailure> rateLimitResult = await CheckGeneralRateLimitsAsync(
                schemaContext, command, mobile.UniqueId, persistorSettings, cancellationToken);

            if (rateLimitResult.IsSome)
            {
                await transaction.RollbackAsync();
                return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(rateLimitResult.Value!);
            }

            VerificationFlowEntity flow = CreateNewVerificationFlow(command, mobile.UniqueId, persistorSettings);
            schemaContext.VerificationFlows.Add(flow);

            await schemaContext.SaveChangesAsync(cancellationToken);
            Log.Information("Successfully saved verification flow. FlowId: {FlowId}", flow.UniqueId);

            await transaction.CommitAsync(cancellationToken);
            Log.Information("Transaction committed successfully for flow {FlowId}", flow.UniqueId);

            return await GetFinalFlowRecordAsync(schemaContext, flow.UniqueId, cancellationToken);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[InitiateFlow] Operation failed. Purpose: {Purpose}", command.Purpose);
            await transaction.RollbackAsync();
            return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InitiateFlowFailed(ex));
        }
    }

    private static async Task<Result<VerificationFlowQueryRecord, VerificationFlowFailure>> GetFinalFlowRecordAsync(
        EcliptixSchemaContext schemaContext,
        Guid flowUniqueId,
        CancellationToken cancellationToken)
    {
        Option<VerificationFlowEntity> flowWithOtpOpt =
            await VerificationFlowQueries.GetByUniqueIdWithActiveOtp(schemaContext, flowUniqueId,
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
        InitiateFlowCommand command,
        Guid mobileUniqueId,
        VerificationFlowPersistorSettings persistorSettings)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return new()
        {
            UniqueId = Guid.NewGuid(),
            MobileNumberId = mobileUniqueId,
            DeviceId = command.AppDeviceId,
            Purpose = command.Purpose,
            Status = VerificationFlowStatus.Pending,
            ExpiresAt = now + persistorSettings.FlowExpiration,
            ConnectionId = command.ConnectId,
            OtpCount = 0,
            CreatedAt = now,
            UpdatedAt = now,
            IsDeleted = false
        };
    }

    private static async Task<Option<VerificationFlowFailure>> CheckGeneralRateLimitsAsync(
        EcliptixSchemaContext schemaContext,
        InitiateFlowCommand command,
        Guid mobileUniqueId,
        VerificationFlowPersistorSettings persistorSettings,
        CancellationToken cancellationToken)
    {
        DateTimeOffset rateLimitLookback = DateTimeOffset.UtcNow - persistorSettings.RateLimitLookback;

        int mobileFlowCount = await VerificationFlowQueries.CountRecentByMobileId(
            schemaContext, mobileUniqueId, rateLimitLookback, cancellationToken);
        if (mobileFlowCount >= persistorSettings.MaxFlowsPerHourPerMobile)
        {
            Log.Warning("[InitiateFlow] Mobile rate limit exceeded. Count: {Count}, Max: {Max}, Mobile: {MobileId}",
                mobileFlowCount, persistorSettings.MaxFlowsPerHourPerMobile, mobileUniqueId);
            return Option<VerificationFlowFailure>.Some(VerificationFlowFailure.RateLimitExceeded());
        }

        int deviceFlowCount = await VerificationFlowQueries.CountRecentByDevice(
            schemaContext, command.AppDeviceId, rateLimitLookback, cancellationToken);
        if (deviceFlowCount >= persistorSettings.MaxFlowsPerHourPerDevice)
        {
            Log.Warning("[InitiateFlow] Device rate limit exceeded. Count: {Count}, Max: {Max}, Device: {DeviceId}",
                deviceFlowCount, persistorSettings.MaxFlowsPerHourPerDevice, command.AppDeviceId);
            return Option<VerificationFlowFailure>.Some(VerificationFlowFailure.DeviceRateLimitExceeded());
        }

        return Option<VerificationFlowFailure>.None;
    }

    private static async Task<Result<MobileNumberEntity, VerificationFlowFailure>> ValidateInputsAsync(
        EcliptixSchemaContext schemaContext,
        InitiateFlowCommand command,
        CancellationToken cancellationToken)
    {
        Option<MobileNumberEntity> mobileOpt =
            await MobileNumberQueries.GetByUniqueId(schemaContext, command.MobileNumberUniqueId, cancellationToken);
        if (!mobileOpt.IsSome)
        {
            Log.Warning("[InitiateFlow] Mobile number not found: {MobileNumberId}", command.MobileNumberUniqueId);
            return Result<MobileNumberEntity, VerificationFlowFailure>.Err(
                VerificationFlowFailure.FromMobileNumber(MobileNumberFailure.NotFound()));
        }

        bool deviceExists = await DeviceQueries.ExistsByDeviceId(schemaContext, command.AppDeviceId, cancellationToken);
        if (!deviceExists)
        {
            Log.Warning("[InitiateFlow] Device not found: {DeviceId}", command.AppDeviceId);
            return Result<MobileNumberEntity, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Validation("Device not found"));
        }

        return Result<MobileNumberEntity, VerificationFlowFailure>.Ok(mobileOpt.Value!);
    }

    private static async Task HandleLingeringActiveFlowAsync(
        EcliptixSchemaContext schemaContext,
        InitiateFlowCommand command,
        CancellationToken cancellationToken)
    {
        Option<VerificationFlowEntity> existingActiveFlowOpt =
            await VerificationFlowQueries.GetActiveFlowForRecovery(
                schemaContext,
                command.MobileNumberUniqueId,
                command.AppDeviceId,
                command.Purpose,
                cancellationToken);

        if (existingActiveFlowOpt.IsSome)
        {
            VerificationFlowEntity existingActiveFlow = existingActiveFlowOpt.Value!;
            DateTimeOffset now = DateTimeOffset.UtcNow;

            await schemaContext.VerificationFlows
                .Where(vf => vf.Id == existingActiveFlow.Id)
                .ExecuteUpdateAsync(setters => setters
                        .SetProperty(vf => vf.Status, VerificationFlowStatus.Expired)
                        .SetProperty(vf => vf.ConnectionId, (long?)null)
                        .SetProperty(vf => vf.ExpiresAt, now)
                        .SetProperty(vf => vf.UpdatedAt, now),
                    cancellationToken);

            await schemaContext.OtpCodes
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
        EcliptixSchemaContext schemaContext,
        InitiateFlowCommand command,
        Guid mobileUniqueId,
        VerificationFlowPersistorSettings persistorSettings,
        CancellationToken cancellationToken)
    {
        Option<VerificationFlowFailure> rateLimitFailure = await CheckPasswordRecoveryRateLimitsAsync(
            schemaContext, command, mobileUniqueId, persistorSettings, cancellationToken);

        if (rateLimitFailure.IsSome)
        {
            return rateLimitFailure;
        }

        await ExpireOldPasswordRecoveryFlowsAsync(schemaContext, mobileUniqueId, cancellationToken);

        return Option<VerificationFlowFailure>.None;
    }

    private static async Task ExpireOldPasswordRecoveryFlowsAsync(
        EcliptixSchemaContext schemaContext,
        Guid mobileUniqueId,
        CancellationToken cancellationToken)
    {
        List<VerificationFlowEntity> oldActiveFlows = await schemaContext.VerificationFlows
            .Where(vf => vf.MobileNumberId == mobileUniqueId &&
                         vf.Purpose == OtpVerificationPurpose.SecureKeyRecovery &&
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
        EcliptixSchemaContext schemaContext,
        InitiateFlowCommand command,
        Guid mobileUniqueId,
        VerificationFlowPersistorSettings persistorSettings,
        CancellationToken cancellationToken)
    {
        DateTimeOffset recoveryLookbackTime =
            DateTimeOffset.UtcNow - persistorSettings.PasswordRecoveryLookback;

        int recoveryCountByMobile = await VerificationFlowQueries.CountRecentPasswordRecovery(
            schemaContext, mobileUniqueId, recoveryLookbackTime, cancellationToken);

        int recoveryCountByDevice = await schemaContext.VerificationFlows
            .Where(f => f.DeviceId == command.AppDeviceId &&
                        f.Purpose == OtpVerificationPurpose.SecureKeyRecovery &&
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
        EcliptixSchemaContext schemaContext,
        RequestResendOtpCommand command,
        CancellationToken cancellationToken)
    {
        try
        {
            Option<VerificationFlowEntity> flowOpt =
                await VerificationFlowQueries.GetByUniqueId(schemaContext, command.FlowUniqueId, cancellationToken);
            if (!flowOpt.IsSome)
            {
                Log.Warning("[RequestResend] Flow not found: {FlowId}", command.FlowUniqueId);
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
            Log.Error(ex, "[RequestResend] Operation failed for flow: {FlowId}", command.FlowUniqueId);
            return Result<(string, uint), VerificationFlowFailure>.Err(
                VerificationFlowFailure.RequestResendFailed(ex));
        }
    }

    private async Task<Result<Unit, VerificationFlowFailure>> UpdateOtpStatusAsync(
        EcliptixSchemaContext schemaContext,
        UpdateOtpStatusCommand command,
        CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await schemaContext.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
        try
        {
            DateTimeOffset utcNow = DateTimeOffset.UtcNow;

            OtpCodeEntity? otp = await schemaContext.OtpCodes
                .Where(o => o.UniqueId == command.OtpIdentified && !o.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken);

            if (otp == null)
            {
                Log.Warning("[UpdateOtpStatus] OTP not found: {OtpId}", command.OtpIdentified);
                await transaction.RollbackAsync();
                return Result<Unit, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.FromOtp(OtpFailure.NotFound()));
            }

            if (otp.Status == command.Status)
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

            otp.Status = command.Status;
            otp.UpdatedAt = utcNow;
            if (command.Status == OtpStatus.Used)
            {
                otp.VerifiedAt = utcNow;
            }

            await schemaContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[UpdateOtpStatus] Operation failed for OTP: {OtpId}", command.OtpIdentified);
            await transaction.RollbackAsync();
            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.UpdateOtpStatusFailed(ex));
        }
    }

    private async Task<Result<MobileNumberQueryRecord, VerificationFlowFailure>> GetMobileNumberAsync(
        EcliptixSchemaContext schemaContext,
        GetMobileNumberQuery query,
        CancellationToken cancellationToken)
    {
        try
        {
            Option<MobileNumberEntity> mobileOpt =
                await MobileNumberQueries.GetByUniqueId(schemaContext, query.MobileNumberIdentifier, cancellationToken);
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
            Log.Error(ex, "[GetMobileNumber] Operation failed for mobile: {MobileId}", query.MobileNumberIdentifier);
            return Result<MobileNumberQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.FromMobileNumber(MobileNumberFailure.GetFailed(ex)));
        }
    }

    private async Task<Result<Unit, VerificationFlowFailure>> UpdateVerificationFlowStatusAsync(
        EcliptixSchemaContext schemaContext,
        UpdateVerificationFlowStatusCommand command,
        CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await schemaContext.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
        try
        {
            VerificationFlowEntity? flow = await schemaContext.VerificationFlows
                .Where(f => f.UniqueId == command.FlowIdentifier && !f.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken);

            if (flow == null)
            {
                Log.Warning("[UpdateFlowStatus] Flow not found: {FlowId}", command.FlowIdentifier);
                await transaction.RollbackAsync();
                return Result<Unit, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.FlowNotFound());
            }

            VerificationFlowStatus newStatus = command.Status;
            OtpVerificationPurpose purpose = flow.Purpose;
            DateTimeOffset utcNow = DateTimeOffset.UtcNow;

            int rowsAffected = await schemaContext.VerificationFlows
                .Where(f => f.UniqueId == command.FlowIdentifier && !f.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                        .SetProperty(f => f.Status, newStatus)
                        .SetProperty(f => f.UpdatedAt, utcNow),
                    cancellationToken);

            if (rowsAffected == 0)
            {
                Log.Warning("[UpdateFlowStatus] Flow not found (no rows affected): {FlowId}", command.FlowIdentifier);
                await transaction.RollbackAsync();
                return Result<Unit, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.FlowNotFound());
            }

            if (newStatus == VerificationFlowStatus.Verified)
            {
                Option<MembershipEntity> membershipOpt =
                    await MembershipQueries.GetByMobileUniqueId(schemaContext, flow.MobileNumberId, cancellationToken);

                if (membershipOpt.IsSome)
                {
                    MembershipEntity membership = membershipOpt.Value!;
                    Guid? accountId = null;
                    Option<AccountEntity> accountOpt =
                        await AccountQueries.GetDefaultAccountByMembershipId(schemaContext, membership.UniqueId);
                    if (accountOpt.IsSome)
                    {
                        accountId = accountOpt.Value!.UniqueId;
                    }

                    schemaContext.VerificationLogs.Add(new VerificationLogEntity
                    {
                        MembershipId = membership.UniqueId,
                        MobileNumberId = flow.MobileNumberId,
                        DeviceId = flow.DeviceId,
                        AccountId = accountId,
                        Purpose = purpose,
                        Status = newStatus,
                        OtpCount = flow.OtpCount,
                        VerifiedAt = utcNow,
                        ExpiresAt = flow.ExpiresAt
                    });

                    await schemaContext.SaveChangesAsync(cancellationToken);
                }
            }

            await transaction.CommitAsync(cancellationToken);

            if (purpose == OtpVerificationPurpose.SecureKeyRecovery && newStatus == VerificationFlowStatus.Verified && _membershipPersistorActor.IsSome)
            {
                Log.Information(
                    "[UPDATE-FLOW-STATUS] Password recovery flow {FlowId} marked as verified. Sending async request to update membership VerificationFlowId",
                    command.FlowIdentifier);

                UpdateMembershipVerificationFlowCommand updateMembershipEvent = new(
                    command.FlowIdentifier,
                    purpose,
                    newStatus,
                    cancellationToken);

                _membershipPersistorActor.Value.Tell(updateMembershipEvent);

                Log.Information("[UPDATE-FLOW-STATUS] Membership update request sent for flow {FlowId}",
                    command.FlowIdentifier);
            }

            return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[UpdateFlowStatus] Operation failed for flow: {FlowId}", command.FlowIdentifier);
            await transaction.RollbackAsync();
            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.UpdateFlowStatusFailed(ex));
        }
    }

    private static async Task<Result<ExistingMembershipResult, VerificationFlowFailure>> CheckExistingMembershipAsync(
        EcliptixSchemaContext schemaContext,
        ExistsMembershipQuery query,
        CancellationToken cancellationToken)
    {
        try
        {
            Option<MembershipEntity> membershipOpt =
                await MembershipQueries.GetByMobileUniqueId(schemaContext, query.MobileNumberId, cancellationToken);

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
                await AccountQueries.GetDefaultAccountByMembershipId(schemaContext, membership.UniqueId);

            ProtoMembership existingMembership = new()
            {
                MembershipId = Helpers.GuidToByteString(membership.UniqueId),
                Status = activityStatus,
                CreationStatus = creationStatus,
                AccountId = accountOpt.IsSome
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
                query.MobileNumberId,
                isTimeout,
                ex.GetType().Name);

            return Result<ExistingMembershipResult, VerificationFlowFailure>.Err(
                VerificationFlowFailure.FromMembership(MembershipFailure.QueryFailed(ex)));
        }
    }

    private async Task<Result<MobileNumberAvailabilityResponse, VerificationFlowFailure>>
        CheckMobileNumberAvailabilityAsync(
            EcliptixSchemaContext schemaContext,
            ExistsMobileNumberQuery query,
            CancellationToken cancellationToken)
    {
        try
        {
            bool mobileNumberExists = await schemaContext.MobileNumbers
                .AnyAsync(mn => mn.UniqueId == query.MobileNumberId && !mn.IsDeleted, cancellationToken);

            if (!mobileNumberExists)
            {
                return Result<MobileNumberAvailabilityResponse, VerificationFlowFailure>.Ok(
                    BuildAvailableResponse());
            }

            MembershipCheckInfo? membershipInfo = await schemaContext.Memberships
                .Where(m => m.MobileNumberId == query.MobileNumberId &&
                            !m.IsDeleted &&
                            !m.MobileNumber.IsDeleted)
                .Select(m => new MembershipCheckInfo
                {
                    MembershipId = m.UniqueId,
                    Status = m.Status,
                    CreationStatus = m.CreationStatus,
                    DeviceId = m.DeviceId,
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

            MobileNumberAvailabilityResponse response = HandleExistingMembership(membershipInfo, query.DeviceId);

            return Result<MobileNumberAvailabilityResponse, VerificationFlowFailure>.Ok(response);
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "[CHECK-AVAILABILITY] Exception checking availability. MobileNumberId={MobileNumberId}, DeviceId={DeviceId}",
                query.MobileNumberId, query.DeviceId);

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
                Status = MobileNumberAvailabilityStatus.MobileNumberAvailabilityRegistrationExpired,
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
                Status = MobileNumberAvailabilityStatus.MobileNumberAvailabilityIncompleteRegistration,
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
            Status = MobileNumberAvailabilityStatus.MobileNumberAvailabilityIncompleteRegistration,
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
            response.AccountId = Helpers.GuidToByteString(info.AccountUniqueId.Value);
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
                    Status = MobileNumberAvailabilityStatus.MobileNumberAvailabilityDataCorruption,
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
        MobileNumberAvailabilityStatus status = isActive
            ? MobileNumberAvailabilityStatus.MobileNumberAvailabilityTakenActive
            : MobileNumberAvailabilityStatus.MobileNumberAvailabilityTakenInactive;
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
            Status = MobileNumberAvailabilityStatus.MobileNumberAvailabilityAvailable,
            CanRegister = true,
            CanContinue = false,
            LocalizationKey = VerificationFlowMessageKeys.MobileAvailableForRegistration
        };
    }

    private async Task<Result<CreateOtpResult, VerificationFlowFailure>> CreateOtpAsync(
        EcliptixSchemaContext schemaContext,
        CreateOtpCommand command,
        CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await schemaContext.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);

        try
        {
            Option<VerificationFlowEntity> flowOpt =
                await VerificationFlowQueries.GetByUniqueId(schemaContext, command.OtpRecord.FlowUniqueId,
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
                    schemaContext, flow.MobileNumberId, rateLimitLookback, cancellationToken);

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

            Guid requestedOtpId = command.OtpRecord.UniqueIdentifier != Guid.Empty
                ? command.OtpRecord.UniqueIdentifier
                : Guid.NewGuid();

            if (command.OtpRecord.UniqueIdentifier != Guid.Empty)
            {
                bool otpAlreadyExists = await schemaContext.OtpCodes
                    .Where(o => o.UniqueId == command.OtpRecord.UniqueIdentifier && !o.IsDeleted)
                    .AnyAsync(cancellationToken);

                if (otpAlreadyExists)
                {
                    await transaction.CommitAsync(cancellationToken);
                    return Result<CreateOtpResult, VerificationFlowFailure>.Ok(new CreateOtpResult
                    {
                        OtpUniqueId = command.OtpRecord.UniqueIdentifier,
                        Outcome = "idempotent"
                    });
                }
            }

            await schemaContext.OtpCodes
                .Where(o => o.VerificationFlowId == flow.Id && o.Status == OtpStatus.Active && !o.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                        .SetProperty(o => o.Status, OtpStatus.Expired)
                        .SetProperty(o => o.UpdatedAt, DateTimeOffset.UtcNow),
                    cancellationToken);

            OtpCodeEntity otp = new()
            {
                UniqueId = requestedOtpId,
                VerificationFlowId = flow.Id,
                OtpValue = command.OtpRecord.OtpHash,
                OtpSalt = command.OtpRecord.OtpSalt,
                Status = command.OtpRecord.Status,
                ExpiresAt = command.OtpRecord.ExpiresAt,
                AttemptCount = 0,
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow,
                IsDeleted = false
            };

            schemaContext.OtpCodes.Add(otp);

            DateTimeOffset now = DateTimeOffset.UtcNow;
            int resendCooldownSeconds = _securityConfig.CurrentValue.VerificationFlow.ResendCooldownBufferSeconds;
            DateTimeOffset resendAvailableAt = now.AddSeconds(resendCooldownSeconds);

            await schemaContext.VerificationFlows
                .Where(f => f.Id == flow.Id)
                .ExecuteUpdateAsync(setters => setters
                        .SetProperty(f => f.OtpCount, f => f.OtpCount + 1)
                        .SetProperty(f => f.LastOtpSentAt, now)
                        .SetProperty(f => f.ResendAvailableAt, resendAvailableAt)
                        .SetProperty(f => f.UpdatedAt, now),
                    cancellationToken);

            await schemaContext.SaveChangesAsync(cancellationToken);

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
        EcliptixSchemaContext schemaContext,
        ValidateMobileNumberCommand command,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(command.MobileNumber))
        {
            return Result<Guid, VerificationFlowFailure>.Err(
                VerificationFlowFailure.MobileNumberInvalid());
        }

        await using IDbContextTransaction transaction =
            await schemaContext.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);

        try
        {
            Option<MobileNumberEntity> existingOpt = await MobileNumberQueries.GetByNumberAndRegion(
                schemaContext, command.MobileNumber, command.RegionCode, cancellationToken);

            if (existingOpt.IsSome)
            {
                await transaction.CommitAsync(cancellationToken);
                return Result<Guid, VerificationFlowFailure>.Ok(existingOpt.Value!.UniqueId);
            }

            MobileNumberEntity mobile = new()
            {
                UniqueId = Guid.NewGuid(),
                Number = command.MobileNumber,
                Region = command.RegionCode,
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow,
                IsDeleted = false
            };

            schemaContext.MobileNumbers.Add(mobile);
            await schemaContext.SaveChangesAsync(cancellationToken);

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
        EcliptixSchemaContext schemaContext,
        VerifyMobileForSecretKeyRecoveryCommand command,
        CancellationToken cancellationToken)
    {
        try
        {
            Option<MobileNumberEntity> mobileOpt = await MobileNumberQueries.GetByNumberAndRegion(
                schemaContext, command.MobileNumber, command.RegionCode, cancellationToken);

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
            AppDeviceIdentifier = flow.DeviceId,
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
        EcliptixSchemaContext schemaContext,
        IncrementOtpAttemptCountCommand command,
        CancellationToken cancellationToken)
    {
        try
        {
            short maxAttempts = (short)_securityConfig.CurrentValue.VerificationFlow.MaxOtpVerificationAttempts;

            int updated = await schemaContext.OtpCodes
                .Where(o => o.UniqueId == command.OtpUniqueId &&
                            o.Status == OtpStatus.Active &&
                            o.AttemptCount < maxAttempts &&
                            !o.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                        .SetProperty(o => o.AttemptCount, o => (short)(o.AttemptCount + 1))
                        .SetProperty(o => o.UpdatedAt, DateTimeOffset.UtcNow),
                    cancellationToken);

            if (updated == 0)
            {
                short? existingCount = await schemaContext.OtpCodes
                    .Where(o => o.UniqueId == command.OtpUniqueId && !o.IsDeleted)
                    .Select(o => (short?)o.AttemptCount)
                    .FirstOrDefaultAsync(cancellationToken);

                if (existingCount == null)
                {
                    return Result<short, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.FromOtp(OtpFailure.NotFound()));
                }

                return Result<short, VerificationFlowFailure>.Ok(existingCount.Value);
            }

            short newCount = await schemaContext.OtpCodes
                .Where(o => o.UniqueId == command.OtpUniqueId && !o.IsDeleted)
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
        EcliptixSchemaContext schemaContext,
        RecordFailedOtpAttemptCommand command,
        CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await schemaContext.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);

        try
        {
            OtpCodeEntity? otp = await schemaContext.OtpCodes
                .Where(o => o.UniqueId == command.OtpUniqueId && !o.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken);

            if (otp == null)
            {
                await transaction.RollbackAsync();
                return Result<Unit, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.FromOtp(OtpFailure.NotFound()));
            }

            FailedOtpAttemptEntity failedAttempt = new()
            {
                OtpCodeId = otp.Id,
                AttemptedValue = "***",
                FailureReason = command.FailureReason,
                AttemptedAt = DateTimeOffset.UtcNow,
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow,
                IsDeleted = false
            };

            schemaContext.FailedOtpAttempts.Add(failedAttempt);
            await schemaContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            Log.Information("[OTP-FAILED-ATTEMPT] Logged failed attempt for OTP {OtpId}, Reason: {Reason}",
                command.OtpUniqueId, command.FailureReason);

            return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync();
            Log.Error(ex, "[OTP-FAILED-ATTEMPT] Error logging failed attempt for OTP {OtpId}", command.OtpUniqueId);
            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.LogAttemptFailed(ex));
        }
    }

    private static async Task<Result<short, VerificationFlowFailure>> GetOtpAttemptCountAsync(
        EcliptixSchemaContext schemaContext,
        GetOtpAttemptCountQuery query,
        CancellationToken cancellationToken)
    {
        try
        {
            var otpData = await schemaContext.OtpCodes
                .Where(o => o.UniqueId == query.OtpUniqueId && !o.IsDeleted)
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
        if (ex is PostgresException pgEx)
        {
            return pgEx.SqlState switch
            {
                PostgresErrorCodes.UniqueViolation => VerificationFlowFailure.ConcurrencyConflict(
                    $"Unique constraint violation: {pgEx.MessageText}"),
                PostgresErrorCodes.ForeignKeyViolation =>
                    VerificationFlowFailure.Validation($"Foreign key constraint violation: {pgEx.MessageText}"),
                PostgresErrorCodes.DeadlockDetected => VerificationFlowFailure.ConcurrencyConflict(
                    $"Deadlock detected: {pgEx.MessageText}"),
                PostgresErrorCodes.SerializationFailure => VerificationFlowFailure.ConcurrencyConflict(
                    $"Serialization failure: {pgEx.MessageText}"),
                PostgresErrorCodes.QueryCanceled =>
                    VerificationFlowFailure.PersistorAccess("Command timeout occurred", pgEx),
                PostgresErrorCodes.ConnectionException or PostgresErrorCodes.ConnectionFailure
                    or PostgresErrorCodes.ConnectionDoesNotExist =>
                    VerificationFlowFailure.PersistorAccess("Network error occurred", pgEx),
                PostgresErrorCodes.InvalidPassword or PostgresErrorCodes.InvalidAuthorizationSpecification =>
                    VerificationFlowFailure.PersistorAccess("Authentication failed", pgEx),
                _ => VerificationFlowFailure.PersistorAccess(
                    $"Database error (Code: {pgEx.SqlState}): {pgEx.MessageText}", pgEx)
            };
        }

        return VerificationFlowFailure.PersistorAccess("Database operation failed", ex);
    }

    private static async Task<Result<FlowStatusQueryRecord, VerificationFlowFailure>> QueryFlowStatusByConnectionIdAsync(
        EcliptixSchemaContext schemaContext,
        GetFlowStatusByConnectionIdQuery query,
        CancellationToken cancellationToken)
    {
        Option<(VerificationFlowStatus Status, DateTimeOffset ExpiresAt)> flowStatusOpt =
            await VerificationFlowQueries.GetFlowStatusByConnectionId(
                schemaContext,
                query.ConnectionId,
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
