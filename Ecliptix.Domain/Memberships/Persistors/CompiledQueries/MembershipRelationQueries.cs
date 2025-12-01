using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class MembershipRelationQueries
{
    public static async Task<MembershipRelationEntity?> GetMembershipRelation(
        EcliptixSchemaContext ctx,
        Guid initiatorMembershipId,
        Guid recipientMembershipId,
        CancellationToken cancellationToken = default)
    {
        long initiatorAccountId = await ctx.Accounts
            .Where(a => a.Membership.UniqueId == initiatorMembershipId)
            .Select(a => a.Id)
            .FirstOrDefaultAsync(cancellationToken);

        long recipientAccountId = await ctx.Accounts
            .Where(a => a.Membership.UniqueId == recipientMembershipId)
            .Select(a => a.Id)
            .FirstOrDefaultAsync(cancellationToken);

        if (initiatorAccountId == 0 || recipientAccountId == 0)
        {
            return null;
        }

        return await ctx.MembershipRelations
            .Include(x => x.InitiatorAccount)
                .ThenInclude(a => a.Membership)
            .Include(x => x.RecipientAccount)
                .ThenInclude(a => a.Membership)
            .FirstOrDefaultAsync(x =>
                (x.InitiatorAccountId == initiatorAccountId && x.RecipientAccountId == recipientAccountId) &&
                !x.IsDeleted,
                cancellationToken);
    }

    public static async Task<bool> ExistsMembershipRelation(
        EcliptixSchemaContext ctx,
        Guid initiatorMembershipId,
        Guid recipientMembershipId,
        CancellationToken cancellationToken = default)
    {
        long initiatorAccountId = await ctx.Accounts
            .Where(a => a.Membership.UniqueId == initiatorMembershipId)
            .Select(a => a.Id)
            .FirstOrDefaultAsync(cancellationToken);

        long recipientAccountId = await ctx.Accounts
            .Where(a => a.Membership.UniqueId == recipientMembershipId)
            .Select(a => a.Id)
            .FirstOrDefaultAsync(cancellationToken);

        if (initiatorAccountId == 0 || recipientAccountId == 0)
        {
            return false;
        }

        return await ctx.MembershipRelations
            .AnyAsync(x =>
                x.InitiatorAccountId == initiatorAccountId &&
                x.RecipientAccountId == recipientAccountId &&
                !x.IsDeleted,
                cancellationToken);
    }
}
