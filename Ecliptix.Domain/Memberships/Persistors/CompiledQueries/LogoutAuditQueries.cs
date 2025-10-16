using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class LogoutAuditQueries
{
    public static readonly Func<EcliptixSchemaContext, Guid, Task<LogoutAuditEntity?>>
        GetMostRecentByMembership = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid membershipUniqueId) =>
                ctx.LogoutAudits
                    .Where(l => l.MembershipUniqueId == membershipUniqueId &&
                                !l.IsDeleted)
                    .OrderByDescending(l => l.LoggedOutAt)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static async Task<List<LogoutAuditEntity>> GetLogoutHistory(
        EcliptixSchemaContext ctx,
        Guid membershipUniqueId,
        int limit)
    {
        return await ctx.LogoutAudits
            .Where(l => l.MembershipUniqueId == membershipUniqueId &&
                        !l.IsDeleted)
            .OrderByDescending(l => l.LoggedOutAt)
            .Take(limit)
            .AsNoTracking()
            .ToListAsync();
    }

    public static readonly Func<EcliptixSchemaContext, Guid, Task<LogoutAuditEntity?>>
        GetByDeviceId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid deviceId) =>
                ctx.LogoutAudits
                    .Where(l => l.DeviceId == deviceId &&
                                !l.IsDeleted)
                    .OrderByDescending(l => l.LoggedOutAt)
                    .AsNoTracking()
                    .FirstOrDefault());
}
