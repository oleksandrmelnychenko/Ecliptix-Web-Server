using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class LogoutAuditQueries
{
    public static readonly Func<EcliptixSchemaContext, Guid, Task<LogoutAudit?>>
        GetMostRecentByMembership = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid membershipUniqueId) =>
                ctx.LogoutAudits
                    .Where(l => l.MembershipUniqueId == membershipUniqueId &&
                                !l.IsDeleted)
                    .OrderByDescending(l => l.LoggedOutAt)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, Guid, int, Task<List<LogoutAudit>>>
        GetLogoutHistory = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid membershipUniqueId, int limit) =>
                ctx.LogoutAudits
                    .Where(l => l.MembershipUniqueId == membershipUniqueId &&
                                !l.IsDeleted)
                    .OrderByDescending(l => l.LoggedOutAt)
                    .Take(limit)
                    .AsNoTracking()
                    .ToList());

    public static readonly Func<EcliptixSchemaContext, uint, Task<LogoutAudit?>>
        GetByConnectId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, uint connectId) =>
                ctx.LogoutAudits
                    .Where(l => l.ConnectId == connectId &&
                                !l.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());
}
