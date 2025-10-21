using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Utilities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class DeviceContextQueries
{
    private static readonly Func<EcliptixSchemaContext, Guid, Guid, Task<DeviceContextEntity?>>
        GetActiveContextCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid membershipId, Guid deviceId) =>
                ctx.DeviceContexts
                    .Where(dc => dc.MembershipId == membershipId &&
                                 dc.DeviceId == deviceId &&
                                 dc.IsActive &&
                                 !dc.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static async Task<Option<DeviceContextEntity>> GetActiveContext(
        EcliptixSchemaContext ctx,
        Guid membershipId,
        Guid deviceId)
    {
        DeviceContextEntity? result = await GetActiveContextCompiled(ctx, membershipId, deviceId);
        return result is not null ? Option<DeviceContextEntity>.Some(result) : Option<DeviceContextEntity>.None;
    }

    private static readonly Func<EcliptixSchemaContext, Guid, Guid, Task<DeviceContextEntity?>>
        GetActiveContextWithAccountCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid membershipId, Guid deviceId) =>
                ctx.DeviceContexts
                    .Include(dc => dc.ActiveAccount)
                    .Where(dc => dc.MembershipId == membershipId &&
                                 dc.DeviceId == deviceId &&
                                 dc.IsActive &&
                                 !dc.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static async Task<Option<DeviceContextEntity>> GetActiveContextWithAccount(
        EcliptixSchemaContext ctx,
        Guid membershipId,
        Guid deviceId)
    {
        DeviceContextEntity? result = await GetActiveContextWithAccountCompiled(ctx, membershipId, deviceId);
        return result is not null ? Option<DeviceContextEntity>.Some(result) : Option<DeviceContextEntity>.None;
    }

    public static async Task<List<DeviceContextEntity>> GetActiveContextsByMembership(
        EcliptixSchemaContext ctx,
        Guid membershipId)
    {
        return await ctx.DeviceContexts
            .Where(dc => dc.MembershipId == membershipId &&
                         dc.IsActive &&
                         !dc.IsDeleted)
            .OrderByDescending(dc => dc.LastActivityAt)
            .AsNoTracking()
            .ToListAsync();
    }

    public static async Task<List<DeviceContextEntity>> GetExpiredContexts(
        EcliptixSchemaContext ctx,
        DateTime now)
    {
        return await ctx.DeviceContexts
            .Where(dc => dc.IsActive &&
                         dc.ContextExpiresAt < now &&
                         !dc.IsDeleted)
            .AsNoTracking()
            .ToListAsync();
    }

    public static readonly Func<EcliptixSchemaContext, Guid, Task<int>>
        CountActiveContextsByDevice = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid deviceId) =>
                ctx.DeviceContexts
                    .Where(dc => dc.DeviceId == deviceId &&
                                 dc.IsActive &&
                                 !dc.IsDeleted)
                    .AsNoTracking()
                    .Count());
}
