using System.Data.Common;
using Akka.Actor;
using Ecliptix.IdentityAccess.Domain.Actors.Membership;
using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.IdentityAccess.Domain.Persistors.CompiledQueries;
using Ecliptix.IdentityAccess.Domain.Schema;
using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Ecliptix.SharedKernel;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Serilog;

namespace Ecliptix.IdentityAccess.Domain.Persistors;

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
        Receive<RecordLogoutCommand>(command =>
        {
            CancellationToken cancellationToken = command.CancellationToken;
            ExecuteWithContext((schemaContext, token) => RecordLogoutAsync(schemaContext, command, token), PersistorOperation.RecordLogout, cancellationToken)
                .PipeTo(Sender);
        });

        Receive<GetLogoutHistoryQuery>(query =>
        {
            CancellationToken cancellationToken = query.CancellationToken;
            ExecuteWithContext((schemaContext, _) => GetLogoutHistoryAsync(schemaContext, query), PersistorOperation.GetLogoutHistory, cancellationToken)
                .PipeTo(Sender);
        });

        Receive<GetMostRecentLogoutQuery>(query =>
        {
            CancellationToken cancellationToken = query.CancellationToken;
            ExecuteWithContext((schemaContext, _) => GetMostRecentLogoutAsync(schemaContext, query), PersistorOperation.GetMostRecentLogout, cancellationToken)
                .PipeTo(Sender);
        });

        Receive<GetLogoutByDeviceQuery>(query =>
        {
            CancellationToken cancellationToken = query.CancellationToken;
            ExecuteWithContext((schemaContext, _) => GetLogoutByDeviceAsync(schemaContext, query), PersistorOperation.GetLogoutByDevice, cancellationToken)
                .PipeTo(Sender);
        });
    }

    private static async Task<Result<Unit, LogoutFailure>> RecordLogoutAsync(
        EcliptixSchemaContext schemaContext,
        RecordLogoutCommand command,
        CancellationToken cancellationToken)
    {
        await using Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction =
            await schemaContext.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            LogoutAuditEntity audit = new()
            {
                MembershipId = command.MembershipUniqueId,
                AccountId = command.AccountId,
                DeviceId = command.DeviceId,
                Reason = command.Reason,
                LoggedOutAt = DateTimeOffset.UtcNow,
                IpAddress = command.IpAddress,
                Platform = command.Platform
            };

            schemaContext.LogoutAudits.Add(audit);
            await schemaContext.SaveChangesAsync(cancellationToken);

            await transaction.CommitAsync(cancellationToken);

            Log.Information(
                "Logout audit recorded - MembershipId: {MembershipId}, DeviceId: {DeviceId}, AccountId: {AccountId}, Reason: {Reason}",
                command.MembershipUniqueId, command.DeviceId, command.AccountId, command.Reason);

            return Result<Unit, LogoutFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            Log.Error(ex, "Failed to record logout audit for MembershipId: {MembershipId}", command.MembershipUniqueId);
            return Result<Unit, LogoutFailure>.Err(
                LogoutFailure.RecordFailed("Failed to record logout audit", ex));
        }
    }

    protected override LogoutFailure MapDbException(DbException ex)
    {
        if (ex is PostgresException pgEx)
        {
            return pgEx.SqlState switch
            {
                PostgresErrorCodes.UniqueViolation =>
                    LogoutFailure.RecordFailed("Duplicate logout record detected", pgEx),
                PostgresErrorCodes.DeadlockDetected => LogoutFailure.DatabaseError(pgEx),
                PostgresErrorCodes.QueryCanceled => LogoutFailure.Timeout(pgEx),
                _ => LogoutFailure.DatabaseError(pgEx)
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
        EcliptixSchemaContext schemaContext,
        GetLogoutHistoryQuery query)
    {
        try
        {
            List<LogoutAuditEntity> history = await LogoutAuditQueries.GetLogoutHistory(
                schemaContext,
                query.MembershipUniqueId,
                query.Limit);

            Log.Information(
                "Retrieved {Count} logout history records for MembershipId: {MembershipId}",
                history.Count, query.MembershipUniqueId);

            return Result<List<LogoutAuditEntity>, LogoutFailure>.Ok(history);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to get logout history for MembershipId: {MembershipId}", query.MembershipUniqueId);
            return Result<List<LogoutAuditEntity>, LogoutFailure>.Err(
                LogoutFailure.QueryFailed("Failed to retrieve logout history", ex));
        }
    }

    private static async Task<Result<Option<LogoutAuditEntity>, LogoutFailure>> GetMostRecentLogoutAsync(
        EcliptixSchemaContext schemaContext,
        GetMostRecentLogoutQuery query)
    {
        try
        {
            Option<LogoutAuditEntity> result = await LogoutAuditQueries.GetMostRecentByMembership(
                schemaContext,
                query.MembershipUniqueId);

            if (result.IsSome)
            {
                Log.Information(
                    "Retrieved most recent logout for MembershipId: {MembershipId}, LoggedOutAt: {LoggedOutAt}",
                    query.MembershipUniqueId, result.Value!.LoggedOutAt);
            }
            else
            {
                Log.Information(
                    "No logout records found for MembershipId: {MembershipId}",
                    query.MembershipUniqueId);
            }

            return Result<Option<LogoutAuditEntity>, LogoutFailure>.Ok(result);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to get most recent logout for MembershipId: {MembershipId}", query.MembershipUniqueId);
            return Result<Option<LogoutAuditEntity>, LogoutFailure>.Err(
                LogoutFailure.QueryFailed("Failed to retrieve most recent logout", ex));
        }
    }

    private static async Task<Result<Option<LogoutAuditEntity>, LogoutFailure>> GetLogoutByDeviceAsync(
        EcliptixSchemaContext schemaContext,
        GetLogoutByDeviceQuery query)
    {
        try
        {
            Option<LogoutAuditEntity> result = await LogoutAuditQueries.GetByDeviceId(
                schemaContext,
                query.DeviceId);

            if (result.IsSome)
            {
                Log.Information(
                    "Retrieved logout for DeviceId: {DeviceId}, LoggedOutAt: {LoggedOutAt}",
                    query.DeviceId, result.Value!.LoggedOutAt);
            }
            else
            {
                Log.Information(
                    "No logout records found for DeviceId: {DeviceId}",
                    query.DeviceId);
            }

            return Result<Option<LogoutAuditEntity>, LogoutFailure>.Ok(result);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to get logout by device for DeviceId: {DeviceId}", query.DeviceId);
            return Result<Option<LogoutAuditEntity>, LogoutFailure>.Err(
                LogoutFailure.QueryFailed("Failed to retrieve logout by device", ex));
        }
    }

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return PersistorSupervisorStrategy.CreateStrategy();
    }
}
