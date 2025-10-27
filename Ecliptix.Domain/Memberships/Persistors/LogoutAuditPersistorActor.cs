using System.Data.Common;
using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents.Logout;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.CompiledQueries;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Utilities;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Serilog;

namespace Ecliptix.Domain.Memberships.Persistors;

public class LogoutAuditPersistorActor : PersistorBase<LogoutFailure>
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
            ExecuteWithContext((ctx, cancellationToken) => RecordLogoutAsync(ctx, cmd, cancellationToken), "RecordLogout", cancellationToken)
                .PipeTo(Sender);
        });

        Receive<GetLogoutHistoryEvent>(cmd =>
        {
            CancellationToken cancellationToken = cmd.CancellationToken;
            ExecuteWithContext((ctx, cancellationToken) => GetLogoutHistoryAsync(ctx, cmd), "GetLogoutHistory", cancellationToken)
                .PipeTo(Sender);
        });

        Receive<GetMostRecentLogoutEvent>(cmd =>
        {
            CancellationToken cancellationToken = cmd.CancellationToken;
            ExecuteWithContext((ctx, cancellationToken) => GetMostRecentLogoutAsync(ctx, cmd), "GetMostRecentLogout", cancellationToken)
                .PipeTo(Sender);
        });

        Receive<GetLogoutByDeviceEvent>(cmd =>
        {
            CancellationToken cancellationToken = cmd.CancellationToken;
            ExecuteWithContext((ctx, cancellationToken) => GetLogoutByDeviceAsync(ctx, cmd), "GetLogoutByDevice", cancellationToken)
                .PipeTo(Sender);
        });
    }

    private static async Task<Result<Unit, LogoutFailure>> RecordLogoutAsync(
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

            return Result<Unit, LogoutFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            Log.Error(ex, "Failed to record logout audit for MembershipId: {MembershipId}", cmd.MembershipUniqueId);
            return Result<Unit, LogoutFailure>.Err(
                LogoutFailure.RecordFailed("Failed to record logout audit", ex));
        }
    }

    protected override LogoutFailure MapDbException(DbException ex)
    {
        if (ex is SqlException sqlEx)
        {
            return sqlEx.Number switch
            {
                2627 or 2601 => LogoutFailure.RecordFailed("Duplicate logout record detected", sqlEx),
                1205 => LogoutFailure.DatabaseError(sqlEx),
                -2 => LogoutFailure.Timeout(sqlEx),
                2 => LogoutFailure.DatabaseError(sqlEx),
                18456 => LogoutFailure.DatabaseError(sqlEx),
                _ => LogoutFailure.DatabaseError(sqlEx)
            };
        }

        return LogoutFailure.DatabaseError(ex);
    }

    protected override LogoutFailure CreateTimeoutFailure(TimeoutException ex)
    {
        return LogoutFailure.Timeout(ex);
    }

    protected override LogoutFailure CreateGenericFailure(Exception ex)
    {
        return LogoutFailure.InternalError("Error while recording logout", ex);
    }

    private static async Task<Result<List<LogoutAuditEntity>, LogoutFailure>> GetLogoutHistoryAsync(
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

            return Result<List<LogoutAuditEntity>, LogoutFailure>.Ok(history);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to get logout history for MembershipId: {MembershipId}", cmd.MembershipUniqueId);
            return Result<List<LogoutAuditEntity>, LogoutFailure>.Err(
                LogoutFailure.QueryFailed("Failed to retrieve logout history", ex));
        }
    }

    private async Task<Result<Option<LogoutAuditEntity>, LogoutFailure>> GetMostRecentLogoutAsync(
        EcliptixSchemaContext schemaContext,
        GetMostRecentLogoutEvent cmd)
    {
        try
        {
            Option<LogoutAuditEntity> result = await LogoutAuditQueries.GetMostRecentByMembership(
                schemaContext,
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

            return Result<Option<LogoutAuditEntity>, LogoutFailure>.Ok(result);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to get most recent logout for MembershipId: {MembershipId}", cmd.MembershipUniqueId);
            return Result<Option<LogoutAuditEntity>, LogoutFailure>.Err(
                LogoutFailure.QueryFailed("Failed to retrieve most recent logout", ex));
        }
    }

    private async Task<Result<Option<LogoutAuditEntity>, LogoutFailure>> GetLogoutByDeviceAsync(
        EcliptixSchemaContext schemaContext,
        GetLogoutByDeviceEvent cmd)
    {
        try
        {
            Option<LogoutAuditEntity> result = await LogoutAuditQueries.GetByDeviceId(
                schemaContext,
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

            return Result<Option<LogoutAuditEntity>, LogoutFailure>.Ok(result);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to get logout by device for DeviceId: {DeviceId}", cmd.DeviceId);
            return Result<Option<LogoutAuditEntity>, LogoutFailure>.Err(
                LogoutFailure.QueryFailed("Failed to retrieve logout by device", ex));
        }
    }

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return PersistorSupervisorStrategy.CreateStrategy();
    }
}
