using System.Threading;
using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class MobileNumberQueries
{
    public static async Task<MobileNumberEntity?> GetByUniqueId(
        EcliptixSchemaContext ecliptixSchemaContext,
        Guid uniqueId,
        CancellationToken cancellationToken = default)
    {
        return await ecliptixSchemaContext.MobileNumbers
            .Where(m => m.UniqueId == uniqueId && !m.IsDeleted)
            .AsNoTracking()
            .FirstOrDefaultAsync(cancellationToken);
    }

    public static async Task<MobileNumberEntity?> GetByNumberAndRegion(
        EcliptixSchemaContext ecliptixSchemaContext,
        string number,
        string? region,
        CancellationToken cancellationToken = default)
    {
        return await ecliptixSchemaContext.MobileNumbers
            .Where(m => m.Number == number &&
                        (m.Region == region || (region == null && m.Region == null)) &&
                        !m.IsDeleted)
            .AsNoTracking()
            .FirstOrDefaultAsync(cancellationToken);
    }
}
