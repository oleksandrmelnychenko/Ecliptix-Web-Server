using System.Data;
using System.Data.Common;
using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents.Common;
using Ecliptix.Domain.Memberships.ActorEvents.Contact;
using MembershipRelationQueries = Ecliptix.Domain.Memberships.Persistors.CompiledQueries.MembershipRelationQueries;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.QueryResults;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Protobuf.Contact;
using Ecliptix.Utilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Serilog;
using ContactFailure = Ecliptix.Domain.Memberships.Failures.ContactFailure;
using ContactStatus = Ecliptix.Domain.Schema.Entities.ContactStatus;

namespace Ecliptix.Domain.Memberships.Persistors;

public class MembershipRelationPersistorActor : PersistorBase<ContactFailure>
{

    private static readonly Dictionary<ContactStatus, Ecliptix.Protobuf.Contact.ContactStatus> StatusMap = new()
    {
        [ContactStatus.Blocked] = Ecliptix.Protobuf.Contact.ContactStatus.Blocked,
        [ContactStatus.Muted] = Ecliptix.Protobuf.Contact.ContactStatus.Muted,
        [ContactStatus.Removed] = Ecliptix.Protobuf.Contact.ContactStatus.None
    };

    public MembershipRelationPersistorActor(IDbContextFactory<EcliptixSchemaContext> dbContextFactory)
        : base(dbContextFactory)
    {
        Become(Ready);
    }

    public static Props Build(IDbContextFactory<EcliptixSchemaContext> dbContextFactory)
    {
        return Props.Create(() => new MembershipRelationPersistorActor(dbContextFactory));
    }

    private void Ready()
    {
        RegisterHandlers();
    }

    private void RegisterHandlers()
    {
        ReceivePersistorCommand<RemoveContactEvent, ModifyContactResult>(
            RemoveFriendAsync,
            "RemoveFriend");

        ReceivePersistorCommand<GetContactStatusEvent, ContactStatusQueryRecord>(
            GetFriendshipStatusAsync,
            "GetFriendshipStatus");

        ReceivePersistorCommand<BlockContactEvent, ModifyContactResult>(
            BlockUserAsync,
            "BlockUser");

        ReceivePersistorCommand<UnblockContactEvent, ModifyContactResult>(
            UnblockUserAsync,
            "UnblockUser");

        ReceivePersistorCommand<ListContactsEvent, ListContactsResponse>(
            ListContactsAsync,
            "ListContacts");

        ReceivePersistorCommand<MuteContactEvent, ModifyContactResult>(
            MuteContactAsync,
            "MuteContact");

        ReceivePersistorCommand<UnmuteContactEvent, ModifyContactResult>(
            UnmuteContactAsync,
            "UnmuteContact");
    }

    private void ReceivePersistorCommand<TMessage, TResult>(
        Func<EcliptixSchemaContext, TMessage, CancellationToken, Task<Result<TResult, ContactFailure>>> handler,
        string operationName)
        where TMessage : class, ICancellableActorEvent
    {
        Receive<TMessage>(message =>
        {
            IActorRef replyTo = Sender;
            CancellationToken messageToken = ExtractCancellationToken(message);

            ExecuteWithContext(Operation, operationName, messageToken).PipeTo(replyTo);
            return;

            Task<Result<TResult, ContactFailure>> Operation(EcliptixSchemaContext schemaContext,
                CancellationToken cancellationToken)
            {
                CancellationToken effectiveToken = CombineCancellationTokens(cancellationToken, messageToken,
                    out CancellationTokenSource? linkedSource);
                try
                {
                    return handler(schemaContext, message, effectiveToken);
                }
                finally
                {
                    linkedSource?.Dispose();
                }
            }
        });
    }

    private static CancellationToken ExtractCancellationToken(object? message)
    {
        return message is ICancellableActorEvent cancellable ? cancellable.CancellationToken : CancellationToken.None;
    }

    private static CancellationToken CombineCancellationTokens(
        CancellationToken first,
        CancellationToken second,
        out CancellationTokenSource? linkedSource)
    {
        linkedSource = null;

        bool firstActive = first.CanBeCanceled;
        bool secondActive = second.CanBeCanceled;

        switch (firstActive)
        {
            case false when !secondActive:
                return CancellationToken.None;
            case false:
                return second;
        }

        if (!secondActive)
        {
            return first;
        }

        linkedSource = CancellationTokenSource.CreateLinkedTokenSource(first, second);
        return linkedSource.Token;
    }

    private async Task<Result<ModifyContactResult, ContactFailure>> RemoveFriendAsync(
        EcliptixSchemaContext ctx,
        RemoveContactEvent evt,
        CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await ctx.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);

        try
        {

            MembershipRelationEntity? relation = await MembershipRelationQueries.GetMembershipRelation(
                ctx,
                evt.MembershipId,
                evt.TargetMembershipId,
                cancellationToken);

            if (relation == null)
            {

                relation = await MembershipRelationQueries.GetMembershipRelation(
                    ctx,
                    evt.TargetMembershipId,
                    evt.MembershipId,
                    cancellationToken);
            }

            if (relation == null)
            {
                return Result<ModifyContactResult, ContactFailure>.Err(
                    ContactFailure.ContactRelationNotFound());
            }

            relation.Status = ContactStatus.Removed;
            await ctx.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            return Result<ModifyContactResult, ContactFailure>.Ok(new ModifyContactResult
            {
                Outcome = "relation_removed"
            });
        }
        catch (Exception ex)
        {

            Log.Error(ex, "[REMOVE-FRIEND-FAILED] Error removing friend relation");
            throw;
        }
    }

    private static async Task<Result<ContactStatusQueryRecord, ContactFailure>> GetFriendshipStatusAsync(
        EcliptixSchemaContext ctx,
        GetContactStatusEvent evt,
        CancellationToken cancellationToken)
    {
        MembershipRelationEntity? relation = await MembershipRelationQueries.GetMembershipRelation(
            ctx,
            evt.MembershipId,
            evt.OtherMembershipId,
            cancellationToken);

        if (relation == null)
        {

            relation = await MembershipRelationQueries.GetMembershipRelation(
                ctx,
                evt.OtherMembershipId,
                evt.MembershipId,
                cancellationToken);
        }

        ContactStatusQueryRecord record = new()
        {
            Status = relation?.Status,
            InitiatorAccountId = relation?.InitiatorAccountId,
            Since = relation?.CreatedAt
        };

        return Result<ContactStatusQueryRecord, ContactFailure>.Ok(record);
    }

    private static async Task<Result<ModifyContactResult, ContactFailure>> BlockUserAsync(
        EcliptixSchemaContext ctx,
        BlockContactEvent evt,
        CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await ctx.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);

        try
        {
            if (evt.ByMembershipId == evt.TargetMembershipId)
            {
                return Result<ModifyContactResult, ContactFailure>.Err(
                    ContactFailure.ValidationFailed("Cannot block yourself"));
            }

            MembershipRelationEntity? existing = await MembershipRelationQueries.GetMembershipRelation(
                ctx,
                evt.ByMembershipId,
                evt.TargetMembershipId,
                cancellationToken);

            if (existing != null)
            {
                if (existing.Status == ContactStatus.Blocked)
                {
                    await transaction.CommitAsync(cancellationToken);
                    return Result<ModifyContactResult, ContactFailure>.Ok(new ModifyContactResult
                    {
                        Outcome = "user_already_blocked"
                    });
                }

                existing.Status = ContactStatus.Blocked;
            }
            else
            {

                long byAccountId = await ctx.Accounts
                    .Where(a => a.Membership.UniqueId == evt.ByMembershipId && !a.IsDeleted)
                    .Select(a => a.Id)
                    .FirstOrDefaultAsync(cancellationToken);

                long targetAccountId = await ctx.Accounts
                    .Where(a => a.Membership.UniqueId == evt.TargetMembershipId && !a.IsDeleted)
                    .Select(a => a.Id)
                    .FirstOrDefaultAsync(cancellationToken);

                if (byAccountId == 0 || targetAccountId == 0)
                {
                    return Result<ModifyContactResult, ContactFailure>.Err(
                        ContactFailure.NotFound("Account not found"));
                }

                MembershipRelationEntity relation = new()
                {
                    InitiatorAccountId = byAccountId,
                    RecipientAccountId = targetAccountId,
                    Status = ContactStatus.Blocked
                };

                ctx.MembershipRelations.Add(relation);
            }

            await ctx.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            return Result<ModifyContactResult, ContactFailure>.Ok(new ModifyContactResult
            {
                Outcome = "user_blocked"
            });
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[BLOCK-USER-FAILED] Error blocking user");
            throw;
        }
    }

    private async Task<Result<ModifyContactResult, ContactFailure>> UnblockUserAsync(
        EcliptixSchemaContext ctx,
        UnblockContactEvent evt,
        CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await ctx.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);

        try
        {
            MembershipRelationEntity? relation = await MembershipRelationQueries.GetMembershipRelation(
                ctx,
                evt.ByMembershipId,
                evt.TargetMembershipId,
                cancellationToken);

            if (relation == null)
            {
                await transaction.CommitAsync(cancellationToken);
                return Result<ModifyContactResult, ContactFailure>.Ok(new ModifyContactResult
                {
                    Outcome = "user_not_blocked"
                });
            }

            if (relation.Status != ContactStatus.Blocked)
            {
                return Result<ModifyContactResult, ContactFailure>.Err(
                    ContactFailure.ValidationFailed("User is not blocked"));
            }

            long byAccountId = await ctx.Accounts
                .Where(a => a.Membership.UniqueId == evt.ByMembershipId && !a.IsDeleted)
                .Select(a => a.Id)
                .FirstOrDefaultAsync(cancellationToken);

            if (byAccountId == 0)
            {
                return Result<ModifyContactResult, ContactFailure>.Err(
                    ContactFailure.NotFound("Account not found"));
            }

            if (relation.InitiatorAccountId != byAccountId)
            {
                return Result<ModifyContactResult, ContactFailure>.Err(
                    ContactFailure.ValidationFailed("Cannot unblock user you didn't block"));
            }

            ctx.MembershipRelations.Remove(relation);
            await ctx.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            Log.Information("[USER-UNBLOCKED] By: {By}, Target: {Target}",
                evt.ByMembershipId, evt.TargetMembershipId);

            return Result<ModifyContactResult, ContactFailure>.Ok(new ModifyContactResult
            {
                Outcome = "user_unblocked"
            });
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[UNBLOCK-USER-FAILED] Error unblocking user");
            throw;
        }
    }

    private static async Task<Result<ListContactsResponse, ContactFailure>> ListContactsAsync(
        EcliptixSchemaContext ctx,
        ListContactsEvent evt,
        CancellationToken cancellationToken)
    {
        try
        {

            long cursorId = 0;
            if (!string.IsNullOrEmpty(evt.Cursor) && !long.TryParse(evt.Cursor, out cursorId))
            {
                return Result<ListContactsResponse, ContactFailure>.Err(
                    ContactFailure.ValidationFailed("Invalid cursor format"));
            }

            List<ContactProjection> allContacts = await MembershipRelationQueries.ListContactsAsync(
                ctx,
                evt.MembershipId,
                cursorId,
                evt.Limit,
                cancellationToken);

            bool hasMore = allContacts.Count > evt.Limit;
            List<ContactProjection> contacts = hasMore
                ? allContacts.Take(evt.Limit).ToList()
                : allContacts;

            ListContactsResponse response = new();

            foreach (ContactProjection projection in contacts)
            {
                Contact contact = new()
                {
                    MembershipId = Google.Protobuf.ByteString.CopyFrom(projection.ContactMembershipId.ToByteArray()),
                    DisplayName = projection.DisplayName ?? projection.ProfileName ?? "Unknown",
                    AvatarUrl = string.Empty, // Avatar URL not yet implemented
                    Since = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTimeOffset(projection.CreatedAt)
                };

                if (projection.Status.HasValue && StatusMap.TryGetValue((ContactStatus)projection.Status.Value, out Protobuf.Contact.ContactStatus protoStatus))
                {
                    contact.Status = protoStatus;
                }

                if (projection.MutedUntil.HasValue)
                {
                    contact.MutedUntil = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTimeOffset(projection.MutedUntil.Value);
                }

                response.Contacts.Add(contact);
            }

            if (hasMore && contacts.Any())
            {
                response.NextCursor = contacts.Last().RelationId.ToString();
            }

            return Result<ListContactsResponse, ContactFailure>.Ok(response);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[LIST-CONTACTS-FAILED] Error listing contacts for membership {MembershipId}", evt.MembershipId);
            return Result<ListContactsResponse, ContactFailure>.Err(
                ContactFailure.ListContactsFailed(ex));
        }
    }

    private static async Task<Result<ModifyContactResult, ContactFailure>> MuteContactAsync(
        EcliptixSchemaContext ctx,
        MuteContactEvent evt,
        CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await ctx.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);

        try
        {
            if (evt.ByMembershipId == evt.TargetMembershipId)
            {
                return Result<ModifyContactResult, ContactFailure>.Err(
                    ContactFailure.ValidationFailed("Cannot mute yourself"));
            }

            MembershipRelationEntity? existing = await MembershipRelationQueries.GetMembershipRelation(
                ctx,
                evt.ByMembershipId,
                evt.TargetMembershipId,
                cancellationToken);

            if (existing != null)
            {
                if (existing.Status == ContactStatus.Muted && existing.MutedUntil == evt.MutedUntil)
                {
                    await transaction.CommitAsync(cancellationToken);
                    return Result<ModifyContactResult, ContactFailure>.Ok(new ModifyContactResult
                    {
                        Outcome = "contact_already_muted"
                    });
                }

                existing.Status = ContactStatus.Muted;
                existing.MutedUntil = evt.MutedUntil;
            }
            else
            {
                long byAccountId = await ctx.Accounts
                    .Where(a => a.Membership.UniqueId == evt.ByMembershipId && !a.IsDeleted)
                    .Select(a => a.Id)
                    .FirstOrDefaultAsync(cancellationToken);

                long targetAccountId = await ctx.Accounts
                    .Where(a => a.Membership.UniqueId == evt.TargetMembershipId && !a.IsDeleted)
                    .Select(a => a.Id)
                    .FirstOrDefaultAsync(cancellationToken);

                if (byAccountId == 0 || targetAccountId == 0)
                {
                    return Result<ModifyContactResult, ContactFailure>.Err(
                        ContactFailure.NotFound("Account not found"));
                }

                MembershipRelationEntity relation = new()
                {
                    InitiatorAccountId = byAccountId,
                    RecipientAccountId = targetAccountId,
                    Status = ContactStatus.Muted,
                    MutedUntil = evt.MutedUntil
                };

                ctx.MembershipRelations.Add(relation);
            }

            await ctx.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            Log.Information("[CONTACT-MUTED] By: {By}, Target: {Target}, Until: {Until}",
                evt.ByMembershipId, evt.TargetMembershipId, evt.MutedUntil);

            return Result<ModifyContactResult, ContactFailure>.Ok(new ModifyContactResult
            {
                Outcome = "contact_muted"
            });
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[MUTE-CONTACT-FAILED] Error muting contact");
            throw;
        }
    }

    private static async Task<Result<ModifyContactResult, ContactFailure>> UnmuteContactAsync(
        EcliptixSchemaContext ctx,
        UnmuteContactEvent evt,
        CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await ctx.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);

        try
        {
            MembershipRelationEntity? relation = await MembershipRelationQueries.GetMembershipRelation(
                ctx,
                evt.ByMembershipId,
                evt.TargetMembershipId,
                cancellationToken);

            if (relation == null)
            {
                await transaction.CommitAsync(cancellationToken);
                return Result<ModifyContactResult, ContactFailure>.Ok(new ModifyContactResult
                {
                    Outcome = "contact_not_muted"
                });
            }

            if (relation.Status != ContactStatus.Muted)
            {
                return Result<ModifyContactResult, ContactFailure>.Err(
                    ContactFailure.ValidationFailed("Contact is not muted"));
            }

            long byAccountId = await ctx.Accounts
                .Where(a => a.Membership.UniqueId == evt.ByMembershipId && !a.IsDeleted)
                .Select(a => a.Id)
                .FirstOrDefaultAsync(cancellationToken);

            if (byAccountId == 0)
            {
                return Result<ModifyContactResult, ContactFailure>.Err(
                    ContactFailure.NotFound("Account not found"));
            }

            if (relation.InitiatorAccountId != byAccountId)
            {
                return Result<ModifyContactResult, ContactFailure>.Err(
                    ContactFailure.ValidationFailed("Cannot unmute contact you didn't mute"));
            }

            relation.Status = null;
            relation.MutedUntil = null;

            await ctx.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            Log.Information("[CONTACT-UNMUTED] By: {By}, Target: {Target}",
                evt.ByMembershipId, evt.TargetMembershipId);

            return Result<ModifyContactResult, ContactFailure>.Ok(new ModifyContactResult
            {
                Outcome = "contact_unmuted"
            });
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[UNMUTE-CONTACT-FAILED] Error unmuting contact");
            throw;
        }
    }

    protected override ContactFailure MapDbException(DbException ex)
    {
        return ContactFailure.DatabaseError($"Database error: {ex.Message}", ex);
    }

    protected override ContactFailure CreateTimeoutFailure(TimeoutException ex)
    {
        return ContactFailure.DatabaseError($"Operation timeout: {ex.Message}", ex);
    }

    protected override ContactFailure CreateGenericFailure(Exception ex)
    {
        return ContactFailure.UnexpectedError($"Unexpected error: {ex.Message}", ex);
    }
}
