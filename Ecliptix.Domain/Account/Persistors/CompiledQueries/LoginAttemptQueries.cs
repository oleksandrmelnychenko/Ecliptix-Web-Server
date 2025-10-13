using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;

namespace Ecliptix.Domain.Account.Persistors.CompiledQueries;

public static class LoginAttemptQueries
{
    public static readonly Func<EcliptixSchemaContext, string, Task<LoginAttemptEntity?>>
        GetMostRecentLockout = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, string mobileNumber) =>
                ctx.LoginAttempts
                    .Join(ctx.MobileNumbers,
                        la => la.MobileNumberId,
                        mn => mn.UniqueId,
                        (la, mn) => new { la, mn })
                    .Where(x => x.mn.Number == mobileNumber &&
                                x.la.LockedUntil != null &&
                                !x.la.IsDeleted &&
                                !x.mn.IsDeleted)
                    .OrderByDescending(x => x.la.Timestamp)
                    .Select(x => x.la)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, string, DateTime, Task<int>>
        CountFailedSince = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, string mobileNumber, DateTime since) =>
                ctx.LoginAttempts
                    .Join(ctx.MobileNumbers,
                        la => la.MobileNumberId,
                        mn => mn.UniqueId,
                        (la, mn) => new { la, mn })
                    .Where(x => x.mn.Number == mobileNumber &&
                                x.la.Timestamp > since &&
                                x.la.LockedUntil == null &&
                                !x.la.IsDeleted &&
                                !x.mn.IsDeleted)
                    .AsNoTracking()
                    .Count());

    
    public static readonly Func<EcliptixSchemaContext, Guid, DateTime, Task<int>>
        CountFailedMembershipCreationSince = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid mobileUniqueId, DateTime since) =>
                ctx.LoginAttempts
                    .Join(ctx.Accounts,
                        la => la.AccountId,
                        a => a.UniqueId,
                        (la, a) => new { la, a })
                    .Where(x => x.a.MobileNumberId == mobileUniqueId &&
                                x.la.Outcome == "membership_creation" &&
                                x.la.Status == "failed" &&
                                x.la.AttemptedAt > since &&
                                !x.la.IsDeleted &&
                                !x.a.IsDeleted)
                    .AsNoTracking()
                    .Count());

    public static readonly Func<EcliptixSchemaContext, Guid, DateTime, Task<DateTime?>>
        GetEarliestFailedMembershipCreationSince = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid mobileUniqueId, DateTime since) =>
                ctx.LoginAttempts
                    .AsNoTracking()
                    .Join(ctx.Accounts,
                        la => la.AccountId,
                        a => a.UniqueId,
                        (la, a) => new { la, a })
                    .Where(x => x.a.MobileNumberId == mobileUniqueId &&
                                x.la.Outcome == "membership_creation" &&
                                x.la.Status == "failed" &&
                                x.la.AttemptedAt > since &&
                                !x.la.IsDeleted)
                    .Select(x => (DateTime?)x.la.AttemptedAt)
                    .Min());
}
