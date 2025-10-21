using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Utilities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class OtpCodeQueries
{
    private static readonly Func<EcliptixSchemaContext, Guid, Task<OtpCodeEntity?>>
        GetByUniqueIdCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid uniqueId) =>
                ctx.OtpCodes
                    .Where(o => o.UniqueId == uniqueId && !o.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static async Task<Option<OtpCodeEntity>> GetByUniqueId(
        EcliptixSchemaContext ctx,
        Guid uniqueId)
    {
        OtpCodeEntity? result = await GetByUniqueIdCompiled(ctx, uniqueId);
        return result is not null ? Option<OtpCodeEntity>.Some(result) : Option<OtpCodeEntity>.None;
    }

    private static readonly Func<EcliptixSchemaContext, long, Task<OtpCodeEntity?>>
        GetActiveByFlowIdCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, long flowId) =>
                ctx.OtpCodes
                    .Where(o => o.VerificationFlowId == flowId &&
                                o.Status == "active" &&
                                !o.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static async Task<Option<OtpCodeEntity>> GetActiveByFlowId(
        EcliptixSchemaContext ctx,
        long flowId)
    {
        OtpCodeEntity? result = await GetActiveByFlowIdCompiled(ctx, flowId);
        return result is not null ? Option<OtpCodeEntity>.Some(result) : Option<OtpCodeEntity>.None;
    }
}
