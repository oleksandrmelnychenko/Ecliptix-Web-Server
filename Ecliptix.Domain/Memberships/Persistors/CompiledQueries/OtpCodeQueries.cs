using Ecliptix.Domain.Memberships;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Utilities;
using Microsoft.EntityFrameworkCore;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class OtpCodeQueries
{
    public static async Task<Option<OtpCodeEntity>> GetByUniqueId(
        EcliptixSchemaContext ctx,
        Guid uniqueId,
        CancellationToken cancellationToken = default)
    {
        OtpCodeEntity? result = await ctx.OtpCodes
            .Where(o => o.UniqueId == uniqueId && !o.IsDeleted)
            .AsNoTracking()
            .FirstOrDefaultAsync(cancellationToken);

        return result is not null ? Option<OtpCodeEntity>.Some(result) : Option<OtpCodeEntity>.None;
    }

    public static async Task<Option<OtpCodeEntity>> GetActiveByFlowId(
        EcliptixSchemaContext ctx,
        long flowId,
        CancellationToken cancellationToken = default)
    {
        OtpCodeEntity? result = await ctx.OtpCodes
            .Where(o => o.VerificationFlowId == flowId &&
                        o.Status == OtpStatus.Active &&
                        !o.IsDeleted)
            .AsNoTracking()
            .FirstOrDefaultAsync(cancellationToken);

        return result is not null ? Option<OtpCodeEntity>.Some(result) : Option<OtpCodeEntity>.None;
    }
}
