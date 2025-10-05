using Microsoft.EntityFrameworkCore;
using Ecliptix.Memberships.Persistor.Schema;
using Ecliptix.Memberships.Persistor.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class MobileNumberQueries
{
    /// <summary>
    /// Get mobile number by UniqueId
    /// </summary>
    public static readonly Func<EcliptixSchemaContext, Guid, Task<MobileNumber?>>
        GetByUniqueId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid uniqueId) =>
                ctx.MobileNumbers
                    .Where(m => m.UniqueId == uniqueId && !m.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    /// <summary>
    /// Get mobile number by number and region (handles null region)
    /// Used for EnsureMobileNumber operation
    /// </summary>
    public static readonly Func<EcliptixSchemaContext, string, string?, Task<MobileNumber?>>
        GetByNumberAndRegion = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, string number, string? region) =>
                ctx.MobileNumbers
                    .Where(m => m.Number == number &&
                                (m.Region == region || (region == null && m.Region == null)) &&
                                !m.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());
}
