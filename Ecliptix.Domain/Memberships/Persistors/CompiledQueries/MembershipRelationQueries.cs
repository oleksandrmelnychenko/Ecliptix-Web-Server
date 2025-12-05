using System.Threading;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class MembershipRelationQueries
{
    private static readonly Func<EcliptixSchemaContext, Guid, Guid, Task<MembershipRelationEntity?>>
        GetMembershipRelationCompiled = EF.CompileAsyncQuery((EcliptixSchemaContext ctx, Guid initiatorMembershipId,
                Guid recipientMembershipId) =>
            ctx.MembershipRelations
                .FirstOrDefault(x =>
                    !x.IsDeleted &&
                    x.InitiatorAccount.Membership.UniqueId == initiatorMembershipId &&
                    x.RecipientAccount.Membership.UniqueId == recipientMembershipId));

    public static Task<MembershipRelationEntity?> GetMembershipRelation(
        EcliptixSchemaContext ctx,
        Guid initiatorMembershipId,
        Guid recipientMembershipId,
        CancellationToken cancellationToken = default)
    {
        return GetMembershipRelationCompiled(ctx, initiatorMembershipId, recipientMembershipId);
    }

    private static readonly Func<EcliptixSchemaContext, Guid, Guid, Task<bool>>
        ExistsMembershipRelationCompiled = EF.CompileAsyncQuery((EcliptixSchemaContext ctx, Guid initiatorMembershipId,
                Guid recipientMembershipId) =>
            ctx.MembershipRelations
                .AsNoTracking()
                .Any(x =>
                    (x.InitiatorAccount.Membership.UniqueId == initiatorMembershipId &&
                     x.RecipientAccount.Membership.UniqueId == recipientMembershipId) &&
                    !x.IsDeleted));

    public static Task<bool> ExistsMembershipRelation(
        EcliptixSchemaContext ctx,
        Guid initiatorMembershipId,
        Guid recipientMembershipId,
        CancellationToken cancellationToken = default)
    {
        return ExistsMembershipRelationCompiled(ctx, initiatorMembershipId, recipientMembershipId);
    }

    public static Task<List<ContactProjection>> ListContactsAsync(
        EcliptixSchemaContext ctx,
        Guid membershipId,
        long cursorId,
        int limit,
        CancellationToken cancellationToken = default)
    {
        int takeCount = limit < int.MaxValue ? limit + 1 : limit;

        return ctx.MembershipRelations
            .AsNoTracking()
            .Where(mr => !mr.IsDeleted
                         && mr.Status != ContactStatus.Removed
                         && mr.Id > cursorId
                         && (mr.InitiatorAccount.Membership.UniqueId == membershipId
                             || mr.RecipientAccount.Membership.UniqueId == membershipId))
            .OrderBy(mr => mr.Id)
            .Take(takeCount)
            .Select(mr => new ContactProjection
            {
                RelationId = mr.Id,
                IsInitiator = mr.InitiatorAccount.Membership.UniqueId == membershipId,
                ContactMembershipId = mr.InitiatorAccount.Membership.UniqueId == membershipId
                    ? mr.RecipientAccount.Membership.UniqueId
                    : mr.InitiatorAccount.Membership.UniqueId,
                DisplayName = mr.InitiatorAccount.Membership.UniqueId == membershipId
                    ? mr.RecipientAccount.Profile.DisplayName
                    : mr.InitiatorAccount.Profile.DisplayName,
                ProfileName = mr.InitiatorAccount.Membership.UniqueId == membershipId
                    ? mr.RecipientAccount.Profile.ProfileName
                    : mr.InitiatorAccount.Profile.ProfileName,
                Status = mr.Status.HasValue ? (byte)mr.Status.Value : null,
                MutedUntil = mr.MutedUntil,
                CreatedAt = mr.CreatedAt
            })
            .ToListAsync(cancellationToken);
    }
}
