using System.Threading;
using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class DeviceQueries
{
    public static async Task<bool> ExistsByUniqueId(
        EcliptixSchemaContext ctx,
        Guid uniqueId,
        CancellationToken cancellationToken = default)
    {
        return await ctx.Devices
            .Where(d => d.UniqueId == uniqueId && !d.IsDeleted)
            .AsNoTracking()
            .AnyAsync(cancellationToken);
    }

    public static async Task<DeviceEntity?> GetByUniqueId(
        EcliptixSchemaContext ctx,
        Guid uniqueId,
        CancellationToken cancellationToken = default)
    {
        return await ctx.Devices
            .Where(d => d.UniqueId == uniqueId && !d.IsDeleted)
            .AsNoTracking()
            .FirstOrDefaultAsync(cancellationToken);
    }

    public static async Task<DeviceEntity?> GetByDeviceId(
        EcliptixSchemaContext ctx,
        Guid deviceId,
        CancellationToken cancellationToken = default)
    {
        return await ctx.Devices
            .Where(d => d.UniqueId == deviceId && !d.IsDeleted)
            .AsNoTracking()
            .FirstOrDefaultAsync(cancellationToken);
    }

    public static async Task<DeviceEntity?> GetByAppInstanceId(
        EcliptixSchemaContext ctx,
        Guid appInstanceId,
        CancellationToken cancellationToken = default)
    {
        return await ctx.Devices
            .Where(d => d.AppInstanceId == appInstanceId && !d.IsDeleted)
            .AsNoTracking()
            .OrderByDescending(d => d.CreatedAt)
            .FirstOrDefaultAsync(cancellationToken);
    }
}
