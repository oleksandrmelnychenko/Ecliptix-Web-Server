using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class DeviceContextQueries
{
    public static readonly Func<EcliptixSchemaContext, Guid, Guid, Task<DeviceContextEntity?>>
        GetActiveContext = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ecliptixSchemaContext, Guid membershipId, Guid deviceId) =>
                ecliptixSchemaContext.DeviceContexts
                    .Where(dc => dc.MembershipId == membershipId &&
                                 dc.DeviceId == deviceId &&
                                 dc.IsActive &&
                                 !dc.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, Guid, Guid, Task<DeviceContextEntity?>>
        GetActiveContextWithAccount = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ecliptixSchemaContext, Guid membershipId, Guid deviceId) =>
                ecliptixSchemaContext.DeviceContexts
                    .Include(dc => dc.ActiveAccount)
                    .Where(dc => dc.MembershipId == membershipId &&
                                 dc.DeviceId == deviceId &&
                                 dc.IsActive &&
                                 !dc.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static async Task<List<DeviceContextEntity>> GetActiveContextsByMembership(
        EcliptixSchemaContext ecliptixSchemaContext,
        Guid membershipId)
    {
        return await ecliptixSchemaContext.DeviceContexts
            .Where(dc => dc.MembershipId == membershipId &&
                         dc.IsActive &&
                         !dc.IsDeleted)
            .OrderByDescending(dc => dc.LastActivityAt)
            .AsNoTracking()
            .ToListAsync();
    }

    public static async Task<List<DeviceContextEntity>> GetExpiredContexts(
        EcliptixSchemaContext ecliptixSchemaContext,
        DateTime now)
    {
        return await ecliptixSchemaContext.DeviceContexts
            .Where(dc => dc.IsActive &&
                         dc.ContextExpiresAt < now &&
                         !dc.IsDeleted)
            .AsNoTracking()
            .ToListAsync();
    }

    public static readonly Func<EcliptixSchemaContext, Guid, Task<int>>
        CountActiveContextsByDevice = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ecliptixSchemaContext, Guid deviceId) =>
                ecliptixSchemaContext.DeviceContexts
                    .Where(dc => dc.DeviceId == deviceId &&
                                 dc.IsActive &&
                                 !dc.IsDeleted)
                    .AsNoTracking()
                    .Count());
}
