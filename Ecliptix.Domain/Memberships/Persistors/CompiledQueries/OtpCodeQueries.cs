using Microsoft.EntityFrameworkCore;
using Ecliptix.Memberships.Persistor.Schema;
using Ecliptix.Memberships.Persistor.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class OtpCodeQueries
{
    /// <summary>
    /// Get OTP code by UniqueId
    /// </summary>
    public static readonly Func<EcliptixSchemaContext, Guid, Task<OtpCode?>>
        GetByUniqueId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid uniqueId) =>
                ctx.OtpCodes
                    .Where(o => o.UniqueId == uniqueId && !o.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    /// <summary>
    /// Get active OTP for a verification flow
    /// </summary>
    public static readonly Func<EcliptixSchemaContext, long, Task<OtpCode?>>
        GetActiveByFlowId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, long flowId) =>
                ctx.OtpCodes
                    .Where(o => o.VerificationFlowId == flowId &&
                                o.Status == "active" &&
                                !o.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());
}
