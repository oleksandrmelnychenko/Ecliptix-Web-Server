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
        try
        {
            LogoutAuditEntity audit = new()
            {
                MembershipUniqueId = cmd.MembershipUniqueId,
                ConnectId = cmd.ConnectId,
                Reason = cmd.Reason,
                LoggedOutAt = DateTime.UtcNow
            };

            ctx.LogoutAudits.Add(audit);
            await ctx.SaveChangesAsync();

            Log.Information(
                "Logout audit recorded - MembershipId: {MembershipId}, ConnectId: {ConnectId}, Reason: {Reason}",
                cmd.MembershipUniqueId, cmd.ConnectId, cmd.Reason);

            return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
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
