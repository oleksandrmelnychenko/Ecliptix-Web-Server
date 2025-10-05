using Microsoft.EntityFrameworkCore;
using Ecliptix.Memberships.Persistor.Schema;
using Ecliptix.Memberships.Persistor.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class LoginAttemptQueries
{
    /// <summary>
    /// Get most recent lockout marker for a mobile number
    /// Returns the latest LoginAttempt with LockedUntil timestamp set
    /// </summary>
    public static readonly Func<EcliptixSchemaContext, string, Task<LoginAttempt?>>
        GetMostRecentLockout = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, string mobileNumber) =>
                ctx.LoginAttempts
                    .Where(l => l.MobileNumber == mobileNumber &&
                                l.LockedUntil != null &&
                                !l.IsDeleted)
                    .OrderByDescending(l => l.Timestamp)
                    .AsNoTracking()
                    .FirstOrDefault());

    /// <summary>
    /// Count failed login attempts in a time window (excluding lockout markers)
    /// Used for rate limiting (5 attempts in 5 minutes)
    /// </summary>
    public static readonly Func<EcliptixSchemaContext, string, DateTime, Task<int>>
        CountFailedSince = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, string mobileNumber, DateTime since) =>
                ctx.LoginAttempts
                    .Where(l => l.MobileNumber == mobileNumber &&
                                l.Timestamp > since &&
                                l.LockedUntil == null &&
                                !l.IsDeleted)
                    .AsNoTracking()
                    .Count());
}
