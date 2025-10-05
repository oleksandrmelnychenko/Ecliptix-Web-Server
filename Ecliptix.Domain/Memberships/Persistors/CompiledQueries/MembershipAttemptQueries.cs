using Microsoft.EntityFrameworkCore;
using Ecliptix.Memberships.Persistor.Schema;
using Ecliptix.Memberships.Persistor.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class MembershipAttemptQueries
{
    /// <summary>
    /// Count failed membership creation attempts since timestamp
    /// Used for rate limiting (5 attempts per hour)
    /// </summary>
    public static readonly Func<EcliptixSchemaContext, Guid, DateTime, Task<int>>
        CountFailedSince = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid mobileUniqueId, DateTime since) =>
                ctx.MembershipAttempts
                    .Join(ctx.Memberships,
                        ma => ma.MembershipId,
                        m => m.UniqueId,
                        (ma, m) => new { ma, m })
                    .Where(x => x.m.MobileNumberId == mobileUniqueId &&
                                x.ma.Status == "failed" &&
                                x.ma.AttemptedAt > since &&
                                !x.ma.IsDeleted &&
                                !x.m.IsDeleted)
                    .AsNoTracking()
                    .Count());

    /// <summary>
    /// Get earliest failed attempt timestamp (for cooldown calculation)
    /// </summary>
    public static readonly Func<EcliptixSchemaContext, Guid, DateTime, Task<DateTime?>>
        GetEarliestFailedSince = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid mobileUniqueId, DateTime since) =>
                ctx.MembershipAttempts
                    .AsNoTracking()
                    .Join(ctx.Memberships,
                        ma => ma.MembershipId,
                        m => m.UniqueId,
                        (ma, m) => new { ma, m })
                    .Where(x => x.m.MobileNumberId == mobileUniqueId &&
                                x.ma.Status == "failed" &&
                                x.ma.AttemptedAt > since &&
                                !x.ma.IsDeleted)
                    .Select(x => (DateTime?)x.ma.AttemptedAt)
                    .Min());
}
