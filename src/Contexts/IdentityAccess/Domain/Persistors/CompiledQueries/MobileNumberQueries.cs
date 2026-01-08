using Ecliptix.IdentityAccess.Domain.Schema;
using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Ecliptix.SharedKernel;
using Microsoft.EntityFrameworkCore;

namespace Ecliptix.IdentityAccess.Domain.Persistors.CompiledQueries;

public static class MobileNumberQueries
{
    public static async Task<Option<MobileNumberEntity>> GetByUniqueId(
        EcliptixSchemaContext ctx,
        Guid uniqueId,
        CancellationToken cancellationToken = default)
    {
        MobileNumberEntity? result = await ctx.MobileNumbers
            .Where(m => m.UniqueId == uniqueId && !m.IsDeleted)
            .AsNoTracking()
            .FirstOrDefaultAsync(cancellationToken);

        return result is not null ? Option<MobileNumberEntity>.Some(result) : Option<MobileNumberEntity>.None;
    }

    public static async Task<Option<MobileNumberEntity>> GetByNumberAndRegion(
        EcliptixSchemaContext ctx,
        string number,
        string? region,
        CancellationToken cancellationToken = default)
    {
        MobileNumberEntity? result = await ctx.MobileNumbers
            .Where(m => m.Number == number &&
                        (m.Region == region || (region == null && m.Region == null)) &&
                        !m.IsDeleted)
            .AsNoTracking()
            .FirstOrDefaultAsync(cancellationToken);

        return result is not null ? Option<MobileNumberEntity>.Some(result) : Option<MobileNumberEntity>.None;
    }
}
