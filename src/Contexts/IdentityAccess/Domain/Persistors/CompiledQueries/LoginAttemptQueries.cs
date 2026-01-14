using Ecliptix.IdentityAccess.Domain.Schema;
using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Ecliptix.SharedKernel;
using Microsoft.EntityFrameworkCore;

namespace Ecliptix.IdentityAccess.Domain.Persistors.CompiledQueries;

public static class LoginAttemptQueries
{

    private static readonly Func<EcliptixSchemaContext, string, Task<LoginAttemptEntity?>>
        GetMostRecentLockoutCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, string mobileNumber) =>
                ctx.LoginAttempts
                    .Where(l => l.MobileNumber == mobileNumber &&
                                l.LockedUntil != null &&
                                !l.IsDeleted)
                    .OrderByDescending(l => l.AttemptedAt)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static async Task<Option<LoginAttemptEntity>> GetMostRecentLockout(
        EcliptixSchemaContext ctx,
        string mobileNumber,
        CancellationToken cancellationToken = default)
    {
        LoginAttemptEntity? result = await GetMostRecentLockoutCompiled(ctx, mobileNumber);
        return result is not null ? Option<LoginAttemptEntity>.Some(result) : Option<LoginAttemptEntity>.None;
    }

    private static readonly Func<EcliptixSchemaContext, string, DateTimeOffset, Task<int>>
        CountFailedSinceCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, string mobileNumber, DateTimeOffset since) =>
                ctx.LoginAttempts
                    .AsNoTracking()
                    .Count(l => l.MobileNumber == mobileNumber &&
                                l.AttemptedAt > since &&
                                !l.IsSuccess &&
                                l.LockedUntil == null &&
                                !l.IsDeleted));

    public static Task<int> CountFailedSince(
        EcliptixSchemaContext ctx,
        string mobileNumber,
        DateTimeOffset since,
        CancellationToken cancellationToken = default)
    {
        return CountFailedSinceCompiled(ctx, mobileNumber, since);
    }

    private static readonly Func<EcliptixSchemaContext, Guid, DateTimeOffset, Task<int>>
        CountFailedMembershipCreationSinceCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid mobileUniqueId, DateTimeOffset since) =>
                ctx.LoginAttempts
                    .AsNoTracking()
                    .Join(ctx.Memberships,
                        la => la.MembershipId,
                        m => m.UniqueId,
                        (la, m) => new { la, m })
                    .Count(x => x.m.MobileNumberId == mobileUniqueId &&
                                x.la.Outcome == "membership_creation" &&
                                !x.la.IsSuccess &&
                                x.la.AttemptedAt > since &&
                                !x.la.IsDeleted &&
                                !x.m.IsDeleted));

    public static Task<int> CountFailedMembershipCreationSince(
        EcliptixSchemaContext ctx,
        Guid mobileUniqueId,
        DateTimeOffset since,
        CancellationToken cancellationToken = default)
    {
        return CountFailedMembershipCreationSinceCompiled(ctx, mobileUniqueId, since);
    }

    private static readonly Func<EcliptixSchemaContext, Guid, DateTimeOffset, Task<DateTimeOffset?>>
        GetEarliestFailedMembershipCreationSinceCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid mobileUniqueId, DateTimeOffset since) =>
                ctx.LoginAttempts
                    .AsNoTracking()
                    .Join(ctx.Memberships,
                        la => la.MembershipId,
                        m => m.UniqueId,
                        (la, m) => new { la, m })
                    .Where(x => x.m.MobileNumberId == mobileUniqueId &&
                                x.la.Outcome == "membership_creation" &&
                                !x.la.IsSuccess &&
                                x.la.AttemptedAt > since &&
                                !x.la.IsDeleted &&
                                !x.m.IsDeleted)
                    .Select(x => (DateTimeOffset?)x.la.AttemptedAt)
                    .Min());

    public static async Task<Option<DateTimeOffset>> GetEarliestFailedMembershipCreationSince(
        EcliptixSchemaContext ctx,
        Guid mobileUniqueId,
        DateTimeOffset since,
        CancellationToken cancellationToken = default)
    {
        DateTimeOffset? result = await GetEarliestFailedMembershipCreationSinceCompiled(ctx, mobileUniqueId, since);

        return result.HasValue
            ? Option<DateTimeOffset>.Some(result.Value)
            : Option<DateTimeOffset>.None;
    }
}
