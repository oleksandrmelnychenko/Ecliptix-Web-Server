using Microsoft.EntityFrameworkCore;
using Ecliptix.Memberships.Persistor.Schema;
using Ecliptix.Memberships.Persistor.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class DeviceQueries
{
    /// <summary>
    /// Check if device exists by UniqueId
    /// Used for validation in InitiateVerificationFlow
    /// </summary>
    public static readonly Func<EcliptixSchemaContext, Guid, Task<bool>>
        ExistsByUniqueId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid uniqueId) =>
                ctx.Devices
                    .Where(d => d.UniqueId == uniqueId && !d.IsDeleted)
                    .AsNoTracking()
                    .Any());

    /// <summary>
    /// Get device by UniqueId
    /// </summary>
    public static readonly Func<EcliptixSchemaContext, Guid, Task<Device?>>
        GetByUniqueId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid uniqueId) =>
                ctx.Devices
                    .Where(d => d.UniqueId == uniqueId && !d.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    /// <summary>
    /// Get device by DeviceId (hardware device identifier)
    /// Used for duplicate detection during device registration
    /// </summary>
    public static readonly Func<EcliptixSchemaContext, Guid, Task<Device?>>
        GetByDeviceId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid deviceId) =>
                ctx.Devices
                    .Where(d => d.DeviceId == deviceId && !d.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());
}
