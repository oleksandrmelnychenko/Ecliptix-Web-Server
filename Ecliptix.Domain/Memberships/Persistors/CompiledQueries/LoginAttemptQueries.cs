using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class LoginAttemptQueries
{
    public static async Task<LoginAttemptEntity?> GetMostRecentLockout(
        EcliptixSchemaContext ctx,
        string mobileNumber,
        CancellationToken cancellationToken = default)
    {
        return await ctx.LoginAttempts
            .Where(l => l.MobileNumber == mobileNumber &&
                        l.LockedUntil != null &&
                        !l.IsDeleted)
            .OrderByDescending(l => l.AttemptedAt)
            .AsNoTracking()
            .FirstOrDefaultAsync(cancellationToken);
    }

    public static async Task<int> CountFailedSince(
        EcliptixSchemaContext ctx,
        string mobileNumber,
        DateTimeOffset since,
        CancellationToken cancellationToken = default)
    {
        return await ctx.LoginAttempts
            .Where(l => l.MobileNumber == mobileNumber &&
                        l.AttemptedAt > since &&
                        !l.IsSuccess &&
                        l.LockedUntil == null &&
                        !l.IsDeleted)
            .AsNoTracking()
            .CountAsync(cancellationToken);
    }

    public static async Task<int> CountFailedMembershipCreationSince(
        EcliptixSchemaContext ctx,
        Guid mobileUniqueId,
        DateTimeOffset since,
        CancellationToken cancellationToken = default)
    {
        return await ctx.LoginAttempts
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
            .CountAsync(cancellationToken);
    }

    public static async Task<DateTimeOffset?> GetEarliestFailedMembershipCreationSince(
        EcliptixSchemaContext ctx,
        Guid mobileUniqueId,
        DateTimeOffset since,
        CancellationToken cancellationToken = default)
    {
        return await ctx.LoginAttempts
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
            .MinAsync(cancellationToken);
    }
}
