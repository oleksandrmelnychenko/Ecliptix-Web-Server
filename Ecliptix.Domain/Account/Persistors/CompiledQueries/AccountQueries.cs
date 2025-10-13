using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;

namespace Ecliptix.Domain.Account.Persistors.CompiledQueries;

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
                    .Join(ctx.MobileDevices,
                        a => a.UniqueId,
                        md => md.AccountId,
                        (a, md) => new { a, md })
                    .Join(ctx.Devices,
                        x => x.md.DeviceId,
                        d => d.UniqueId,
                        (x, d) => new { x.a, x.md, d })
                    .Where(x => x.a.MobileNumberId == mobileUniqueId &&
                                x.d.DeviceId == deviceId &&
                                x.md.IsActive &&
                                !x.a.IsDeleted &&
                                !x.md.IsDeleted &&
                                !x.d.IsDeleted)
                    .Select(x => x.a)
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
                    .Join(ctx.MobileNumbers,
                        a => a.MobileNumberId,
                        mn => mn.UniqueId,
                        (a, mn) => new { a, mn })
                    .Where(x => x.mn.UniqueId == mobileUniqueId &&
                                !x.a.IsDeleted &&
                                !x.mn.IsDeleted)
                    .OrderByDescending(x => x.a.UpdatedAt)
                    .Select(x => x.a)
                    .AsNoTracking()
                    .FirstOrDefault());
}
