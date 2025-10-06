using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class LoginAttemptQueries
{
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
