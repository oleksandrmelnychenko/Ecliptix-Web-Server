using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class DeviceQueries
{
    public static readonly Func<EcliptixSchemaContext, Guid, Task<bool>>
        ExistsByUniqueId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid uniqueId) =>
                ctx.Devices
                    .Where(d => d.UniqueId == uniqueId && !d.IsDeleted)
                    .AsNoTracking()
                    .Any());

    public static readonly Func<EcliptixSchemaContext, Guid, Task<Device?>>
        GetByUniqueId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid uniqueId) =>
                ctx.Devices
                    .Where(d => d.UniqueId == uniqueId && !d.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, Guid, Task<Device?>>
        GetByDeviceId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid deviceId) =>
                ctx.Devices
                    .Where(d => d.DeviceId == deviceId && !d.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());
}
