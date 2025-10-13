using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class LoginAttemptQueries
{
    public static readonly Func<EcliptixSchemaContext, MobileNumberEntity, Task<LoginAttemptEntity?>>
        GetMostRecentLockout = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, MobileNumberEntity mobileNumber) =>
                ctx.LoginAttempts
                    .Where(l => l.MobileNumber == mobileNumber &&
                                l.LockedUntil != null &&
                                !l.IsDeleted)
                    .OrderByDescending(l => l.Timestamp)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, MobileNumberEntity, DateTime, Task<int>>
        CountFailedSince = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, MobileNumberEntity mobileNumber, DateTime since) =>
                ctx.LoginAttempts
                    .Where(l => l.MobileNumber == mobileNumber &&
                                l.Timestamp > since &&
                                l.LockedUntil == null &&
                                !l.IsDeleted)
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
