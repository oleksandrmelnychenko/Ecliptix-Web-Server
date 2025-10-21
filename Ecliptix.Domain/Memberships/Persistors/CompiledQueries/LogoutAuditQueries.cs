using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Utilities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class LogoutAuditQueries
{
    private static readonly Func<EcliptixSchemaContext, Guid, Task<LogoutAuditEntity?>>
        GetMostRecentByMembershipCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid membershipUniqueId) =>
                ctx.LogoutAudits
                    .Where(l => l.MembershipUniqueId == membershipUniqueId &&
                                !l.IsDeleted)
                    .OrderByDescending(l => l.LoggedOutAt)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static async Task<Option<LogoutAuditEntity>> GetMostRecentByMembership(
        EcliptixSchemaContext ctx,
        Guid membershipUniqueId)
    {
        LogoutAuditEntity? result = await GetMostRecentByMembershipCompiled(ctx, membershipUniqueId);
        return result is not null ? Option<LogoutAuditEntity>.Some(result) : Option<LogoutAuditEntity>.None;
    }

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

    private static readonly Func<EcliptixSchemaContext, Guid, Task<LogoutAuditEntity?>>
        GetByDeviceIdCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid deviceId) =>
                ctx.LogoutAudits
                    .Where(l => l.DeviceId == deviceId &&
                                !l.IsDeleted)
                    .OrderByDescending(l => l.LoggedOutAt)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static async Task<Option<LogoutAuditEntity>> GetByDeviceId(
        EcliptixSchemaContext ctx,
        Guid deviceId)
    {
        LogoutAuditEntity? result = await GetByDeviceIdCompiled(ctx, deviceId);
        return result is not null ? Option<LogoutAuditEntity>.Some(result) : Option<LogoutAuditEntity>.None;
    }
}
