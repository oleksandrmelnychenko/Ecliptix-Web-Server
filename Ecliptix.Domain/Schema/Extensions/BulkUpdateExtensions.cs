using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Query;

namespace Ecliptix.Domain.Schema.Extensions;

public static class BulkUpdateExtensions
{
    public static Task<int> ExecuteUpdateWithAuditAsync<T>(
        this IQueryable<T> query,
        Expression<Func<SetPropertyCalls<T>, SetPropertyCalls<T>>> setPropertyCalls,
        CancellationToken cancellationToken = default) where T : EntityBase
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;

        Expression<Func<SetPropertyCalls<T>, SetPropertyCalls<T>>> chainedSetters =
            setters => setPropertyCalls.Compile()(setters).SetProperty(e => e.UpdatedAt, now);

        return query.ExecuteUpdateAsync(chainedSetters, cancellationToken);
    }

    public static Task<int> ExecuteSoftDeleteAsync<T>(
        this IQueryable<T> query,
        CancellationToken cancellationToken = default) where T : EntityBase
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;

        return query.ExecuteUpdateAsync(setters => setters
            .SetProperty(e => e.IsDeleted, true)
            .SetProperty(e => e.UpdatedAt, now),
            cancellationToken);
    }
}
