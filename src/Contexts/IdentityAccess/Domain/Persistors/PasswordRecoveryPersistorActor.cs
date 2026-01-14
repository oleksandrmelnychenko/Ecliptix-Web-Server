using System.Data.Common;
using Akka.Actor;
using Ecliptix.IdentityAccess.Domain.Memberships;
using Ecliptix.IdentityAccess.Domain.Actors.VerificationFlow;
using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.IdentityAccess.Domain.Schema;
using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Actors;
using Ecliptix.SharedKernel.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Options;
using Npgsql;
using Serilog;

namespace Ecliptix.IdentityAccess.Domain.Persistors;

public class PasswordRecoveryPersistorActor : PersistorBase<SecretKeyRecoveryFailure>
{
    private readonly IOptionsMonitor<SecurityConfiguration> _securityConfig;

    public PasswordRecoveryPersistorActor(
        IDbContextFactory<EcliptixSchemaContext> dbContextFactory,
        IOptionsMonitor<SecurityConfiguration> securityConfig)
        : base(dbContextFactory)
    {
        _securityConfig = securityConfig;
        Become(Ready);
    }

    public static Props Build(
        IDbContextFactory<EcliptixSchemaContext> dbContextFactory,
        IOptionsMonitor<SecurityConfiguration> securityConfig)
    {
        return Props.Create(() => new PasswordRecoveryPersistorActor(dbContextFactory, securityConfig));
    }

    private void Ready()
    {
        ReceivePersistorCommand<ValidatePasswordRecoveryFlowCommand, PasswordRecoveryFlowValidationResponse>(
            ValidatePasswordRecoveryFlowAsync,
            PersistorOperation.ValidatePasswordRecoveryFlow);

        ReceivePersistorCommand<ExpirePasswordRecoveryFlowsCommand, Unit>(
            ExpirePasswordRecoveryFlowsAsync,
            PersistorOperation.ExpirePasswordRecoveryFlows);
    }

    private void ReceivePersistorCommand<TMessage, TResult>(
        Func<EcliptixSchemaContext, TMessage, CancellationToken, Task<Result<TResult, SecretKeyRecoveryFailure>>> handler,
        PersistorOperation operationName)
        where TMessage : class, ICancellableActorEvent
    {
        Receive<TMessage>(message =>
        {
            IActorRef replyTo = Sender;
            CancellationToken messageToken = ExtractCancellationToken(message);

            ExecuteWithContext(Operation, operationName, messageToken).PipeTo(replyTo);

            return;

            Task<Result<TResult, SecretKeyRecoveryFailure>> Operation(EcliptixSchemaContext schemaContext,
                CancellationToken cancellationToken) =>
                handler(schemaContext, message, cancellationToken);
        });
    }

    private static CancellationToken ExtractCancellationToken(ICancellableActorEvent message) =>
        message.CancellationToken;

    private async Task<Result<PasswordRecoveryFlowValidationResponse, SecretKeyRecoveryFailure>>
        ValidatePasswordRecoveryFlowAsync(
            EcliptixSchemaContext schemaContext,
            ValidatePasswordRecoveryFlowCommand command,
            CancellationToken cancellationToken)
    {
        try
        {
            MembershipPersistorSettings persistorSettings = _securityConfig.CurrentValue.MembershipPersistor;
            DateTimeOffset recoveryValidationStart =
                DateTimeOffset.UtcNow - persistorSettings.PasswordRecoveryValidationWindow;

            MembershipEntity? membership = await schemaContext.Memberships
                .Where(m => m.UniqueId == command.MembershipIdentifier && !m.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken);

            if (membership == null)
            {
                Log.Warning("[PASSWORD-RECOVERY-VALIDATION] Membership not found: {MembershipId}",
                    command.MembershipIdentifier);
                return Result<PasswordRecoveryFlowValidationResponse, SecretKeyRecoveryFailure>.Ok(
                    new PasswordRecoveryFlowValidationResponse(false, null));
            }

            VerificationFlowEntity? recoveryFlow = await schemaContext.VerificationFlows
                .Where(vf => vf.UniqueId == membership.VerificationFlowId &&
                             vf.Purpose == OtpVerificationPurpose.SecureKeyRecovery &&
                             vf.Status == VerificationFlowStatus.Verified &&
                             vf.UpdatedAt >= recoveryValidationStart &&
                             !vf.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken);

            if (recoveryFlow == null)
            {
                VerificationFlowEntity? existingFlow = await schemaContext.VerificationFlows
                    .Where(vf => vf.UniqueId == membership.VerificationFlowId && !vf.IsDeleted)
                    .FirstOrDefaultAsync(cancellationToken);

                if (existingFlow != null)
                {
                    TimeSpan elapsed = DateTimeOffset.UtcNow - existingFlow.UpdatedAt;
                    Log.Warning(
                        "[PASSWORD-RECOVERY-VALIDATION] Recovery flow invalid. MembershipId: {MembershipId}, FlowId: {FlowId}, Purpose: {Purpose}, Status: {Status}, ElapsedMinutes: {Minutes}",
                        command.MembershipIdentifier, existingFlow.UniqueId, existingFlow.Purpose, existingFlow.Status,
                        elapsed.TotalMinutes);
                }
                else
                {
                    Log.Warning(
                        "[PASSWORD-RECOVERY-VALIDATION] No verification flow found for membership: {MembershipId}, ExpectedFlowId: {FlowId}",
                        command.MembershipIdentifier, membership.VerificationFlowId);
                }

                return Result<PasswordRecoveryFlowValidationResponse, SecretKeyRecoveryFailure>.Ok(
                    new PasswordRecoveryFlowValidationResponse(false, null));
            }

            Log.Information(
                "[PASSWORD-RECOVERY-VALIDATION] Valid recovery flow found. MembershipId: {MembershipId}, FlowId: {FlowId}",
                command.MembershipIdentifier, recoveryFlow.UniqueId);

            return Result<PasswordRecoveryFlowValidationResponse, SecretKeyRecoveryFailure>.Ok(
                new PasswordRecoveryFlowValidationResponse(true, recoveryFlow.UniqueId));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[PASSWORD-RECOVERY-VALIDATION] Exception during validation for MembershipId: {MembershipId}",
                command.MembershipIdentifier);
            return Result<PasswordRecoveryFlowValidationResponse, SecretKeyRecoveryFailure>.Err(
                SecretKeyRecoveryFailure.VerificationFailed(ex.Message));
        }
    }

    private static async Task<Result<Unit, SecretKeyRecoveryFailure>> ExpirePasswordRecoveryFlowsAsync(
        EcliptixSchemaContext schemaContext, ExpirePasswordRecoveryFlowsCommand command, CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await schemaContext.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            MembershipEntity? membership = await schemaContext.Memberships
                .Where(m => m.UniqueId == command.MembershipIdentifier && !m.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken);

            if (membership == null)
            {
                await RollbackSilentlyAsync(transaction);
                Log.Warning("[PASSWORD-RECOVERY-EXPIRE] Membership not found: {MembershipId}",
                    command.MembershipIdentifier);
                return Result<Unit, SecretKeyRecoveryFailure>.Ok(Unit.Value);
            }

            int rowsAffected = await schemaContext.VerificationFlows
                .Where(vf => vf.UniqueId == membership.VerificationFlowId &&
                             vf.Purpose == OtpVerificationPurpose.SecureKeyRecovery &&
                             vf.Status == VerificationFlowStatus.Verified &&
                             !vf.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(vf => vf.Status, VerificationFlowStatus.Expired)
                    .SetProperty(vf => vf.UpdatedAt, DateTimeOffset.UtcNow), cancellationToken);

            if (rowsAffected > 0)
            {
                Log.Information(
                    "[PASSWORD-RECOVERY-EXPIRE] Expired {Count} recovery flow(s) for MembershipId: {MembershipId}, FlowId: {FlowId}",
                    rowsAffected, command.MembershipIdentifier, membership.VerificationFlowId);
            }
            else
            {
                Log.Warning(
                    "[PASSWORD-RECOVERY-EXPIRE] No verified recovery flows to expire for MembershipId: {MembershipId}, FlowId: {FlowId}",
                    command.MembershipIdentifier, membership.VerificationFlowId);
            }

            await transaction.CommitAsync(cancellationToken);
            return Result<Unit, SecretKeyRecoveryFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            await RollbackSilentlyAsync(transaction);
            Log.Error(ex, "[PASSWORD-RECOVERY-EXPIRE] Exception while expiring flows for MembershipId: {MembershipId}",
                command.MembershipIdentifier);
            return Result<Unit, SecretKeyRecoveryFailure>.Err(
                SecretKeyRecoveryFailure.PersistorAccess(ex.Message, ex));
        }
    }

    private static async Task RollbackSilentlyAsync(IDbContextTransaction transaction)
    {
        try
        {
            await transaction.RollbackAsync(CancellationToken.None);
        }
        catch
        {

        }
    }

    protected override SecretKeyRecoveryFailure MapDbException(DbException ex)
    {
        if (ex is PostgresException pgEx)
        {
            return pgEx.SqlState switch
            {
                PostgresErrorCodes.DeadlockDetected => SecretKeyRecoveryFailure.DatabaseError(pgEx),
                PostgresErrorCodes.QueryCanceled => SecretKeyRecoveryFailure.Timeout(pgEx),
                _ => SecretKeyRecoveryFailure.DatabaseError(pgEx)
            };
        }

        return SecretKeyRecoveryFailure.DatabaseError(ex);
    }

    protected override SecretKeyRecoveryFailure CreateTimeoutFailure(TimeoutException ex)
    {
        return SecretKeyRecoveryFailure.Timeout(ex);
    }

    protected override SecretKeyRecoveryFailure CreateGenericFailure(Exception ex)
    {
        return SecretKeyRecoveryFailure.InternalError(
            $"Unexpected error in password recovery persistor: {ex.Message}", ex);
    }

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return PersistorSupervisorStrategy.CreateStrategy();
    }
}
