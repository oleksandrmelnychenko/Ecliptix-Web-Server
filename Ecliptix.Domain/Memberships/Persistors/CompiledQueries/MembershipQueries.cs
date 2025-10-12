using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class MembershipQueries
{
    public static readonly Func<EcliptixSchemaContext, string, Task<MembershipEntity?>>
        GetByMobileNumber = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, string mobileNumber) =>
                ctx.Memberships
                    .Join(ctx.MobileNumbers,
                        m => m.MobileNumberId,
                        mn => mn.UniqueId,
                        (m, mn) => new { m, mn })
                    .Where(x => x.mn.Number == mobileNumber &&
                                !x.m.IsDeleted &&
                                !x.mn.IsDeleted)
                    .Select(x => x.m)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, Guid, Guid, Task<MembershipEntity?>>
        GetByMobileUniqueIdAndDevice = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid mobileUniqueId, Guid deviceId) =>
                ctx.Memberships
                    .Where(m => m.MobileNumberId == mobileUniqueId &&
                                m.AppDeviceId == deviceId &&
                                !m.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, Guid, Task<MembershipEntity?>>
        GetByUniqueId = EF.CompileAsyncQuery((EcliptixSchemaContext ctx, Guid uniqueId) =>
            ctx.Memberships
                .Where(m => m.UniqueId == uniqueId && !m.IsDeleted)
                .AsNoTracking()
                .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, Guid, Task<MembershipEntity?>>
        GetByMobileUniqueId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid mobileUniqueId) =>
                ctx.Memberships
                    .Include(m => m.MobileNumber)
                    .Include(m => m.VerificationFlow)
                    .Where(m => m.MobileNumber!.UniqueId == mobileUniqueId && 
                                !m.IsDeleted && 
                                !m.MobileNumber.IsDeleted)
                    .OrderByDescending(m => m.UpdatedAt)
                .FirstOrDefault());
}
