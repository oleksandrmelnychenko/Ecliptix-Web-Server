using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class OtpCodeQueries
{
    public static readonly Func<EcliptixSchemaContext, Guid, Task<OtpCodeEntity?>>
        GetByUniqueId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid uniqueId) =>
                ctx.OtpCodes
                    .Where(o => o.UniqueId == uniqueId && !o.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, long, Task<OtpCodeEntity?>>
        GetActiveByFlowId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, long flowId) =>
                ctx.OtpCodes
                    .Where(o => o.VerificationFlowId == flowId &&
                                o.Status == "active" &&
                                !o.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());
}
