using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class LoginAttemptQueries
{
    public static readonly Func<EcliptixSchemaContext, string, Task<LoginAttemptEntity?>>
        GetMostRecentLockout = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, string mobileNumber) =>
                ctx.LoginAttempts
                    .Where(l => l.MobileNumber == mobileNumber &&
                                l.LockedUntil != null &&
                                !l.IsDeleted)
                    .OrderByDescending(l => l.AttemptedAt)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, string, DateTimeOffset, Task<int>>
        CountFailedSince = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, string mobileNumber, DateTimeOffset since) =>
                ctx.LoginAttempts
                    .Where(l => l.MobileNumber == mobileNumber &&
                                l.AttemptedAt > since &&
                                !l.IsSuccess &&
                                l.LockedUntil == null &&
                                !l.IsDeleted)
                    .AsNoTracking()
                    .Count());

    public static readonly Func<EcliptixSchemaContext, Guid, DateTimeOffset, Task<int>>
        CountFailedMembershipCreationSince = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid mobileUniqueId, DateTimeOffset since) =>
                ctx.LoginAttempts
                    .Join(ctx.Memberships,
                        la => la.MembershipUniqueId,
                        m => m.UniqueId,
                        (la, m) => new { la, m })
                    .Where(x => x.m.MobileNumberId == mobileUniqueId &&
                                x.la.Outcome == "membership_creation" &&
                                !x.la.IsSuccess &&
                                x.la.AttemptedAt > since &&
                                !x.la.IsDeleted &&
                                !x.m.IsDeleted)
                    .AsNoTracking()
                    .Count());

    public static readonly Func<EcliptixSchemaContext, Guid, DateTimeOffset, Task<DateTimeOffset?>>
        GetEarliestFailedMembershipCreationSince = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid mobileUniqueId, DateTimeOffset since) =>
                ctx.LoginAttempts
                    .AsNoTracking()
                    .Join(ctx.Memberships,
                        la => la.MembershipUniqueId,
                        m => m.UniqueId,
                        (la, m) => new { la, m })
                    .Where(x => x.m.MobileNumberId == mobileUniqueId &&
                                x.la.Outcome == "membership_creation" &&
                                !x.la.IsSuccess &&
                                x.la.AttemptedAt > since &&
                                !x.la.IsDeleted)
                    .Select(x => (DateTimeOffset?)x.la.AttemptedAt)
                    .Min());
}
