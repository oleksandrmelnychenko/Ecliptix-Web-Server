using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class MobileNumberQueries
{
    public static readonly Func<EcliptixSchemaContext, Guid, Task<MobileNumber?>>
        GetByUniqueId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid uniqueId) =>
                ctx.MobileNumbers
                    .Where(m => m.UniqueId == uniqueId && !m.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

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
