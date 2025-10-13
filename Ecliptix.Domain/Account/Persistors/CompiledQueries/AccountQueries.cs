using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class AccountQueries
{
    public static readonly Func<EcliptixSchemaContext, string, Task<AccountEntity?>>
        GetByMobileNumber = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, string mobileNumber) =>
                ctx.Accounts
                    .Join(ctx.MobileNumbers,
                        a => a.MobileNumberId,
                        mn => mn.UniqueId,
                        (m, mn) => new { m, mn })
                    .Where(x => x.mn.Number == mobileNumber &&
                                !x.m.IsDeleted &&
                                !x.mn.IsDeleted)
                    .Select(x => x.m)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, Guid, Guid, Task<AccountEntity?>>
        GetByMobileUniqueIdAndDevice = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid mobileUniqueId, Guid deviceId) =>
                ctx.Accounts
                    .Where(a => a.MobileNumberId == mobileUniqueId &&
                                a.AppDeviceId == deviceId &&
                                !a.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, Guid, Task<AccountEntity?>>
        GetByUniqueId = EF.CompileAsyncQuery((EcliptixSchemaContext ctx, Guid uniqueId) =>
            ctx.Accounts
                .Where(a => a.UniqueId == uniqueId && !a.IsDeleted)
                .AsNoTracking()
                .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, Guid, Task<AccountEntity?>>
        GetByMobileUniqueId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid mobileUniqueId) =>
                ctx.Accounts
                    .Include(a => a.MobileNumber)
                    .Include(a => a.VerificationFlow)
                    .Where(a => a.MobileNumber!.UniqueId == mobileUniqueId &&
                                !a.IsDeleted &&
                                !a.MobileNumber.IsDeleted)
                    .OrderByDescending(m => m.UpdatedAt)
                .FirstOrDefault());
}
