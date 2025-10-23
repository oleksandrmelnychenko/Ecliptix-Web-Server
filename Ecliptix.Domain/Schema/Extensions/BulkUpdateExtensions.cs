using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Query;

namespace Ecliptix.Domain.Schema.Extensions;

/// <summary>
/// Extension methods for bulk update operations with automatic audit timestamp management
/// </summary>
public static class BulkUpdateExtensions
{
    /// <summary>
    /// Execute a bulk update with automatic UpdatedAt timestamp
    /// This ensures consistent audit trail across all bulk update operations
    /// </summary>
    /// <typeparam name="T">Entity type derived from EntityBase</typeparam>
    /// <param name="query">The queryable to update</param>
    /// <param name="setPropertyCalls">Property setters expression</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Number of rows affected</returns>
    /// <example>
    /// await ctx.Memberships
    ///     .Where(m => m.UniqueId == id)
    ///     .ExecuteUpdateWithAuditAsync(s => s
    ///         .SetProperty(m => m.Status, "active"));
    /// </example>
    public static Task<int> ExecuteUpdateWithAuditAsync<T>(
        this IQueryable<T> query,
        Expression<Func<SetPropertyCalls<T>, SetPropertyCalls<T>>> setPropertyCalls,
        CancellationToken cancellationToken = default) where T : EntityBase
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;

        // Chain the user's property setters with UpdatedAt
        Expression<Func<SetPropertyCalls<T>, SetPropertyCalls<T>>> chainedSetters =
            setters => setPropertyCalls.Compile()(setters).SetProperty(e => e.UpdatedAt, now);

        return query.ExecuteUpdateAsync(chainedSetters, cancellationToken);
    }

    /// <summary>
    /// Execute a bulk delete with soft delete flag and automatic audit timestamps
    /// Sets IsDeleted = true and UpdatedAt = now
    /// </summary>
    /// <typeparam name="T">Entity type derived from EntityBase</typeparam>
    /// <param name="query">The queryable to soft delete</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Number of rows affected</returns>
    /// <example>
    /// await ctx.Accounts
    ///     .Where(a => a.MembershipId == id)
    ///     .ExecuteSoftDeleteAsync();
    /// </example>
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
