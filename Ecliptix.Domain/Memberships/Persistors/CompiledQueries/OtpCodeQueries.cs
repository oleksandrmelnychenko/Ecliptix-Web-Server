using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Domain.Status;
using Microsoft.EntityFrameworkCore;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class OtpCodeQueries
{
    public static readonly Func<EcliptixSchemaContext, Guid, Task<OtpCodeEntity?>>
        GetByUniqueId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ecliptixSchemaContext, Guid uniqueId) =>
                ecliptixSchemaContext.OtpCodes
                    .Where(o => o.UniqueId == uniqueId && !o.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, long, Task<OtpCodeEntity?>>
        GetActiveByFlowId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ecliptixSchemaContext, long flowId) =>
                ecliptixSchemaContext.OtpCodes
                    .Where(o => o.VerificationFlowId == flowId &&
                                o.Status == StatusCatalog.Otp.Active &&
                                !o.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());
}
