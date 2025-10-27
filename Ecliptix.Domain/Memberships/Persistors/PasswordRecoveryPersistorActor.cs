using System.Data.Common;
using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents.Common;
using Ecliptix.Domain.Memberships.ActorEvents.VerificationFlow;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Configuration;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Options;
using Serilog;

namespace Ecliptix.Domain.Memberships.Persistors;

public class PasswordRecoveryPersistorActor : PersistorBase<PasswordRecoveryFailure>
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
        ReceivePersistorCommand<ValidatePasswordRecoveryFlowEvent, PasswordRecoveryFlowValidation>(
            ValidatePasswordRecoveryFlowAsync,
            "ValidatePasswordRecoveryFlow");

        ReceivePersistorCommand<ExpirePasswordRecoveryFlowsEvent, Unit>(
            ExpirePasswordRecoveryFlowsAsync,
            "ExpirePasswordRecoveryFlows");
    }

    private void ReceivePersistorCommand<TMessage, TResult>(
        Func<EcliptixSchemaContext, TMessage, CancellationToken, Task<Result<TResult, PasswordRecoveryFailure>>> handler,
        string operationName)
        where TMessage : class, ICancellableActorEvent
    {
        Receive<TMessage>(message =>
        {
            IActorRef replyTo = Sender;
            CancellationToken messageToken = ExtractCancellationToken(message);

            ExecuteWithContext(Operation, operationName, messageToken).PipeTo(replyTo);

            return;

            Task<Result<TResult, PasswordRecoveryFailure>> Operation(EcliptixSchemaContext ctx,
                CancellationToken cancellationToken) =>
                handler(ctx, message, cancellationToken);
        });
    }

    private static CancellationToken ExtractCancellationToken(ICancellableActorEvent message) =>
        message.CancellationToken;

    private async Task<Result<PasswordRecoveryFlowValidation, PasswordRecoveryFailure>>
        ValidatePasswordRecoveryFlowAsync(
            EcliptixSchemaContext ctx,
            ValidatePasswordRecoveryFlowEvent cmd,
            CancellationToken cancellationToken)
    {
        try
        {
            MembershipPersistorSettings persistorSettings = _securityConfig.CurrentValue.MembershipPersistor;
            DateTimeOffset recoveryValidationStart =
                DateTimeOffset.UtcNow - persistorSettings.PasswordRecoveryValidationWindow;

            MembershipEntity? membership = await ctx.Memberships
                .Where(m => m.UniqueId == cmd.MembershipIdentifier && !m.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken);

            if (membership == null)
            {
                Log.Warning("[PASSWORD-RECOVERY-VALIDATION] Membership not found: {MembershipId}",
                    cmd.MembershipIdentifier);
                return Result<PasswordRecoveryFlowValidation, PasswordRecoveryFailure>.Ok(
                    new PasswordRecoveryFlowValidation(false, null));
            }

            VerificationFlowEntity? recoveryFlow = await ctx.VerificationFlows
                .Where(vf => vf.UniqueId == membership.VerificationFlowId &&
                             vf.Purpose == VerificationPurpose.PasswordRecovery &&
                             vf.Status == VerificationFlowStatus.Verified &&
                             vf.UpdatedAt >= recoveryValidationStart &&
                             !vf.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken);

            if (recoveryFlow == null)
            {
                VerificationFlowEntity? existingFlow = await ctx.VerificationFlows
                    .Where(vf => vf.UniqueId == membership.VerificationFlowId && !vf.IsDeleted)
                    .FirstOrDefaultAsync(cancellationToken);

                if (existingFlow != null)
                {
                    TimeSpan elapsed = DateTimeOffset.UtcNow - existingFlow.UpdatedAt;
                    Log.Warning(
                        "[PASSWORD-RECOVERY-VALIDATION] Recovery flow invalid. MembershipId: {MembershipId}, FlowId: {FlowId}, Purpose: {Purpose}, Status: {Status}, ElapsedMinutes: {Minutes}",
                        cmd.MembershipIdentifier, existingFlow.UniqueId, existingFlow.Purpose, existingFlow.Status,
                        elapsed.TotalMinutes);
                }
                else
                {
                    Log.Warning(
                        "[PASSWORD-RECOVERY-VALIDATION] No verification flow found for membership: {MembershipId}, ExpectedFlowId: {FlowId}",
                        cmd.MembershipIdentifier, membership.VerificationFlowId);
                }

                return Result<PasswordRecoveryFlowValidation, PasswordRecoveryFailure>.Ok(
                    new PasswordRecoveryFlowValidation(false, null));
            }

            Log.Information(
                "[PASSWORD-RECOVERY-VALIDATION] Valid recovery flow found. MembershipId: {MembershipId}, FlowId: {FlowId}",
                cmd.MembershipIdentifier, recoveryFlow.UniqueId);

            return Result<PasswordRecoveryFlowValidation, PasswordRecoveryFailure>.Ok(
                new PasswordRecoveryFlowValidation(true, recoveryFlow.UniqueId));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[PASSWORD-RECOVERY-VALIDATION] Exception during validation for MembershipId: {MembershipId}",
                cmd.MembershipIdentifier);
            return Result<PasswordRecoveryFlowValidation, PasswordRecoveryFailure>.Err(
                PasswordRecoveryFailure.VerificationFailed(ex.Message));
        }
    }

    private static async Task<Result<Unit, PasswordRecoveryFailure>> ExpirePasswordRecoveryFlowsAsync(
        EcliptixSchemaContext schemaContext, ExpirePasswordRecoveryFlowsEvent cmd, CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await schemaContext.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            MembershipEntity? membership = await schemaContext.Memberships
                .Where(m => m.UniqueId == cmd.MembershipIdentifier && !m.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken);

            if (membership == null)
            {
                await RollbackSilentlyAsync(transaction);
                Log.Warning("[PASSWORD-RECOVERY-EXPIRE] Membership not found: {MembershipId}",
                    cmd.MembershipIdentifier);
                return Result<Unit, PasswordRecoveryFailure>.Ok(Unit.Value);
            }

            int rowsAffected = await schemaContext.VerificationFlows
                .Where(vf => vf.UniqueId == membership.VerificationFlowId &&
                             vf.Purpose == VerificationPurpose.PasswordRecovery &&
                             vf.Status == VerificationFlowStatus.Verified &&
                             !vf.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(vf => vf.Status, VerificationFlowStatus.Expired)
                    .SetProperty(vf => vf.UpdatedAt, DateTimeOffset.UtcNow), cancellationToken);

            if (rowsAffected > 0)
            {
                Log.Information(
                    "[PASSWORD-RECOVERY-EXPIRE] Expired {Count} recovery flow(s) for MembershipId: {MembershipId}, FlowId: {FlowId}",
                    rowsAffected, cmd.MembershipIdentifier, membership.VerificationFlowId);
            }
            else
            {
                Log.Warning(
                    "[PASSWORD-RECOVERY-EXPIRE] No verified recovery flows to expire for MembershipId: {MembershipId}, FlowId: {FlowId}",
                    cmd.MembershipIdentifier, membership.VerificationFlowId);
            }

            await transaction.CommitAsync(cancellationToken);
            return Result<Unit, PasswordRecoveryFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            await RollbackSilentlyAsync(transaction);
            Log.Error(ex, "[PASSWORD-RECOVERY-EXPIRE] Exception while expiring flows for MembershipId: {MembershipId}",
                cmd.MembershipIdentifier);
            return Result<Unit, PasswordRecoveryFailure>.Err(
                PasswordRecoveryFailure.PersistorAccess(ex.Message, ex));
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
            // Swallow rollback exceptions
        }
    }

    protected override PasswordRecoveryFailure MapDbException(DbException ex)
    {
        if (ex is SqlException sqlEx)
        {
            return sqlEx.Number switch
            {
                1205 => PasswordRecoveryFailure.DatabaseError(sqlEx),
                -2 => PasswordRecoveryFailure.Timeout(sqlEx),
                2 => PasswordRecoveryFailure.DatabaseError(sqlEx),
                18456 => PasswordRecoveryFailure.DatabaseError(sqlEx),
                _ => PasswordRecoveryFailure.DatabaseError(sqlEx)
            };
        }

        return PasswordRecoveryFailure.DatabaseError(ex);
    }

    protected override PasswordRecoveryFailure CreateTimeoutFailure(TimeoutException ex)
    {
        return PasswordRecoveryFailure.Timeout(ex);
    }

    protected override PasswordRecoveryFailure CreateGenericFailure(Exception ex)
    {
        return PasswordRecoveryFailure.InternalError(
            $"Unexpected error in password recovery persistor: {ex.Message}", ex);
    }

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return PersistorSupervisorStrategy.CreateStrategy();
    }
}
