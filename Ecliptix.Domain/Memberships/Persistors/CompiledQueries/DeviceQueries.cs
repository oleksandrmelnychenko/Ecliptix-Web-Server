using System.Threading;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Utilities;
using Microsoft.EntityFrameworkCore;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class DeviceQueries
{
    public static async Task<bool> ExistsByDeviceId(
        EcliptixSchemaContext ctx,
        Guid deviceId,
        CancellationToken cancellationToken = default)
    {
        return await ctx.Devices
            .Where(d => d.DeviceId == deviceId && !d.IsDeleted)
            .AsNoTracking()
            .AnyAsync(cancellationToken);
    }

    public static async Task<Option<DeviceEntity>> GetByAppInstanceId(
        EcliptixSchemaContext ctx,
        Guid appInstanceId,
        CancellationToken cancellationToken = default)
    {
        DeviceEntity? result = await ctx.Devices
            .Where(d => d.AppInstanceId == appInstanceId && !d.IsDeleted)
            .AsNoTracking()
            .OrderByDescending(d => d.CreatedAt)
            .FirstOrDefaultAsync(cancellationToken);

        return result is not null ? Option<DeviceEntity>.Some(result) : Option<DeviceEntity>.None;
    }
}
