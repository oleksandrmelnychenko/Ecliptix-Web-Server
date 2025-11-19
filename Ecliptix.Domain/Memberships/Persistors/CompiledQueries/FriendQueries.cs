using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class FriendQueries
{
    private static (Guid, Guid) CanonicalPair(Guid a, Guid b)
    {
        return a.CompareTo(b) < 0 ? (a, b) : (b, a);
    }

    public static async Task<FriendEntity?> GetFriendRelation(
        EcliptixSchemaContext ctx,
        Guid userA,
        Guid userB,
        CancellationToken cancellationToken = default)
    {
        (Guid ua, Guid ub) = CanonicalPair(userA, userB);

        return await ctx.FriendRelations
            .FirstOrDefaultAsync(x => x.UserAId == ua && x.UserBId == ub && !x.IsDeleted, cancellationToken);
    }

    public static async Task<List<FriendEntity>> GetFriendsList(
        EcliptixSchemaContext ctx,
        Guid membershipId,
        int limit,
        CancellationToken cancellationToken = default)
    {
        return await ctx.FriendRelations
            .Where(x => (x.UserAId == membershipId || x.UserBId == membershipId) &&
                        x.Status == FriendRelationStatus.Accepted &&
                        !x.IsDeleted)
            .OrderByDescending(x => x.AcceptedAt)
            .Take(limit)
            .ToListAsync(cancellationToken);
    }

    public static async Task<List<FriendEntity>> GetPendingRequestsIncoming(
        EcliptixSchemaContext ctx,
        Guid membershipId,
        int limit,
        CancellationToken cancellationToken = default)
    {
        return await ctx.FriendRelations
            .Where(x => (x.UserAId == membershipId || x.UserBId == membershipId) &&
                        x.Status == FriendRelationStatus.Pending &&
                        x.RequestedById != membershipId &&
                        !x.IsDeleted)
            .OrderByDescending(x => x.CreatedAt)
            .Take(limit)
            .ToListAsync(cancellationToken);
    }

    public static async Task<List<FriendEntity>> GetPendingRequestsOutgoing(
        EcliptixSchemaContext ctx,
        Guid membershipId,
        int limit,
        CancellationToken cancellationToken = default)
    {
        return await ctx.FriendRelations
            .Where(x => (x.UserAId == membershipId || x.UserBId == membershipId) &&
                        x.Status == FriendRelationStatus.Pending &&
                        x.RequestedById == membershipId &&
                        !x.IsDeleted)
            .OrderByDescending(x => x.CreatedAt)
            .Take(limit)
            .ToListAsync(cancellationToken);
    }

    public static async Task<bool> ExistsFriendRelation(
        EcliptixSchemaContext ctx,
        Guid userA,
        Guid userB,
        CancellationToken cancellationToken = default)
    {
        (Guid ua, Guid ub) = CanonicalPair(userA, userB);

        return await ctx.FriendRelations
            .AnyAsync(x => x.UserAId == ua && x.UserBId == ub && !x.IsDeleted, cancellationToken);
    }
}

