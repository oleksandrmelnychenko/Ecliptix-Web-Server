using System.Data.Common;
using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
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
            ExecuteWithContext(ctx => RecordLogoutAsync(ctx, cmd), "RecordLogout")
                .PipeTo(Sender));
    }

    private async Task<Result<Unit, VerificationFlowFailure>> RecordLogoutAsync(
        EcliptixSchemaContext ctx, RecordLogoutEvent cmd)
    {
        await using Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction = await ctx.Database.BeginTransactionAsync();
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
            await ctx.SaveChangesAsync();

            await transaction.CommitAsync();

            Log.Information(
                "Logout audit recorded - MembershipId: {MembershipId}, DeviceId: {DeviceId}, AccountId: {AccountId}, Reason: {Reason}",
                cmd.MembershipUniqueId, cmd.DeviceId, cmd.AccountId, cmd.Reason);

            return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync();
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
}
