using System.Data.Common;
using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.CompiledQueries;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Utilities;
using Microsoft.EntityFrameworkCore;
using Serilog;

namespace Ecliptix.Domain.Memberships.Persistors;

public class LogoutAuditPersistorActor : PersistorBase<VerificationFlowFailure>
{
    public LogoutAuditPersistorActor(IDbContextFactory<EcliptixSchemaContext> dbContextFactory)
        : base(dbContextFactory)
    {
        Become(Ready);
    }

    public static Props Build(IDbContextFactory<EcliptixSchemaContext> dbContextFactory)
    {
        return Props.Create(() => new LogoutAuditPersistorActor(dbContextFactory));
    }

    private void Ready()
    {
        Receive<RecordLogoutEvent>(cmd =>
        {
            CancellationToken cancellationToken = cmd.CancellationToken;
            ExecuteWithContext((ctx, ct) => RecordLogoutAsync(ctx, cmd, ct), "RecordLogout", cancellationToken)
                .PipeTo(Sender);
        });

        Receive<GetLogoutHistoryEvent>(cmd =>
        {
            CancellationToken cancellationToken = cmd.CancellationToken;
            ExecuteWithContext((ctx, ct) => GetLogoutHistoryAsync(ctx, cmd), "GetLogoutHistory", cancellationToken)
                .PipeTo(Sender);
        });

        Receive<GetMostRecentLogoutEvent>(cmd =>
        {
            CancellationToken cancellationToken = cmd.CancellationToken;
            ExecuteWithContext((ctx, ct) => GetMostRecentLogoutAsync(ctx, cmd), "GetMostRecentLogout", cancellationToken)
                .PipeTo(Sender);
        });

        Receive<GetLogoutByDeviceEvent>(cmd =>
        {
            CancellationToken cancellationToken = cmd.CancellationToken;
            ExecuteWithContext((ctx, ct) => GetLogoutByDeviceAsync(ctx, cmd), "GetLogoutByDevice", cancellationToken)
                .PipeTo(Sender);
        });
    }

    private static async Task<Result<Unit, VerificationFlowFailure>> RecordLogoutAsync(
        EcliptixSchemaContext ctx,
        RecordLogoutEvent cmd,
        CancellationToken cancellationToken)
    {
        await using Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction =
            await ctx.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            LogoutAuditEntity audit = new()
            {
                MembershipUniqueId = cmd.MembershipUniqueId,
                AccountId = cmd.AccountId,
                DeviceId = cmd.DeviceId,
                Reason = cmd.Reason,
                LoggedOutAt = DateTimeOffset.UtcNow,
                IpAddress = cmd.IpAddress,
                Platform = cmd.Platform
            };

            ctx.LogoutAudits.Add(audit);
            await ctx.SaveChangesAsync(cancellationToken);

            await transaction.CommitAsync(cancellationToken);

            Log.Information(
                "Logout audit recorded - MembershipId: {MembershipId}, DeviceId: {DeviceId}, AccountId: {AccountId}, Reason: {Reason}",
                cmd.MembershipUniqueId, cmd.DeviceId, cmd.AccountId, cmd.Reason);

            return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            Log.Error(ex, "Failed to record logout audit for MembershipId: {MembershipId}", cmd.MembershipUniqueId);
            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess("Failed to record logout audit", ex));
        }
    }

    protected override VerificationFlowFailure MapDbException(DbException ex)
    {
        Log.Error(ex, "Database exception in LogoutAuditPersistorActor");
        return VerificationFlowFailure.PersistorAccess("Database error while recording logout", ex);
    }

    protected override VerificationFlowFailure CreateTimeoutFailure(TimeoutException ex)
    {
        Log.Error(ex, "Timeout in LogoutAuditPersistorActor");
        return VerificationFlowFailure.PersistorAccess("Timeout while recording logout", ex);
    }

    protected override VerificationFlowFailure CreateGenericFailure(Exception ex)
    {
        Log.Error(ex, "Generic failure in LogoutAuditPersistorActor");
        return VerificationFlowFailure.PersistorAccess("Error while recording logout", ex);
    }

    private static async Task<Result<List<LogoutAuditEntity>, VerificationFlowFailure>> GetLogoutHistoryAsync(
        EcliptixSchemaContext ctx,
        GetLogoutHistoryEvent cmd)
    {
        try
        {
            List<LogoutAuditEntity> history = await LogoutAuditQueries.GetLogoutHistory(
                ctx,
                cmd.MembershipUniqueId,
                cmd.Limit);

            Log.Information(
                "Retrieved {Count} logout history records for MembershipId: {MembershipId}",
                history.Count, cmd.MembershipUniqueId);

            return Result<List<LogoutAuditEntity>, VerificationFlowFailure>.Ok(history);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to get logout history for MembershipId: {MembershipId}", cmd.MembershipUniqueId);
            return Result<List<LogoutAuditEntity>, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess("Failed to retrieve logout history", ex));
        }
    }

    private async Task<Result<Option<LogoutAuditEntity>, VerificationFlowFailure>> GetMostRecentLogoutAsync(
        EcliptixSchemaContext ctx,
        GetMostRecentLogoutEvent cmd)
    {
        try
        {
            Option<LogoutAuditEntity> result = await LogoutAuditQueries.GetMostRecentByMembership(
                ctx,
                cmd.MembershipUniqueId);

            if (result.HasValue)
            {
                Log.Information(
                    "Retrieved most recent logout for MembershipId: {MembershipId}, LoggedOutAt: {LoggedOutAt}",
                    cmd.MembershipUniqueId, result.Value!.LoggedOutAt);
            }
            else
            {
                Log.Information(
                    "No logout records found for MembershipId: {MembershipId}",
                    cmd.MembershipUniqueId);
            }

            return Result<Option<LogoutAuditEntity>, VerificationFlowFailure>.Ok(result);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to get most recent logout for MembershipId: {MembershipId}", cmd.MembershipUniqueId);
            return Result<Option<LogoutAuditEntity>, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess("Failed to retrieve most recent logout", ex));
        }
    }

    private async Task<Result<Option<LogoutAuditEntity>, VerificationFlowFailure>> GetLogoutByDeviceAsync(
        EcliptixSchemaContext ctx,
        GetLogoutByDeviceEvent cmd)
    {
        try
        {
            Option<LogoutAuditEntity> result = await LogoutAuditQueries.GetByDeviceId(
                ctx,
                cmd.DeviceId);

            if (result.HasValue)
            {
                Log.Information(
                    "Retrieved logout for DeviceId: {DeviceId}, LoggedOutAt: {LoggedOutAt}",
                    cmd.DeviceId, result.Value!.LoggedOutAt);
            }
            else
            {
                Log.Information(
                    "No logout records found for DeviceId: {DeviceId}",
                    cmd.DeviceId);
            }

            return Result<Option<LogoutAuditEntity>, VerificationFlowFailure>.Ok(result);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to get logout by device for DeviceId: {DeviceId}", cmd.DeviceId);
            return Result<Option<LogoutAuditEntity>, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess("Failed to retrieve logout by device", ex));
        }
    }
}
