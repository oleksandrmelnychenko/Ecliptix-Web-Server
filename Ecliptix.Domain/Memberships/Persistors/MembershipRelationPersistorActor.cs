using System.Data.Common;
using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents.Common;
using Ecliptix.Domain.Memberships.ActorEvents.Friend;
using Ecliptix.Domain.Memberships.Failures;
using MembershipRelationQueries = Ecliptix.Domain.Memberships.Persistors.CompiledQueries.MembershipRelationQueries;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.QueryResults;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Utilities;
using Microsoft.EntityFrameworkCore;
using Serilog;

namespace Ecliptix.Domain.Memberships.Persistors;

public class MembershipRelationPersistorActor : PersistorBase<FriendFailure>
{
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
        ReceivePersistorCommand<RemoveFriendEvent, ModifyFriendRelationResult>(
            RemoveFriendAsync,
            "RemoveFriend");

        ReceivePersistorCommand<GetFriendshipStatusEvent, FriendshipStatusQueryRecord>(
            GetFriendshipStatusAsync,
            "GetFriendshipStatus");

        ReceivePersistorCommand<BlockUserEvent, ModifyFriendRelationResult>(
            BlockUserAsync,
            "BlockUser");

        ReceivePersistorCommand<UnblockUserEvent, ModifyFriendRelationResult>(
            UnblockUserAsync,
            "UnblockUser");
    }

    private void ReceivePersistorCommand<TMessage, TResult>(
        Func<EcliptixSchemaContext, TMessage, CancellationToken, Task<Result<TResult, FriendFailure>>> handler,
        string operationName)
        where TMessage : class, ICancellableActorEvent
    {
        Receive<TMessage>(message =>
        {
            IActorRef replyTo = Sender;
            CancellationToken messageToken = ExtractCancellationToken(message);

            ExecuteWithContext(Operation, operationName, messageToken).PipeTo(replyTo);
            return;

            Task<Result<TResult, FriendFailure>> Operation(EcliptixSchemaContext schemaContext,
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

        if (!firstActive && !secondActive)
            return CancellationToken.None;
        if (!firstActive)
            return second;
        if (!secondActive)
            return first;

        linkedSource = CancellationTokenSource.CreateLinkedTokenSource(first, second);
        return linkedSource.Token;
    }

    private async Task<Result<ModifyFriendRelationResult, FriendFailure>> RemoveFriendAsync(
        EcliptixSchemaContext ctx,
        RemoveFriendEvent evt,
        CancellationToken cancellationToken)
    {
        MembershipRelationEntity? relation = await MembershipRelationQueries.GetMembershipRelation(
            ctx,
            evt.MembershipId,
            evt.FriendMembershipId,
            cancellationToken);

        if (relation == null)
        {
            relation = await MembershipRelationQueries.GetMembershipRelation(
                ctx,
                evt.FriendMembershipId,
                evt.MembershipId,
                cancellationToken);
        }

        if (relation == null)
        {
            return Result<ModifyFriendRelationResult, FriendFailure>.Err(
                FriendFailure.FriendRelationNotFound());
        }

        relation.Status = MembershipRelationStatus.Removed;
        await ctx.SaveChangesAsync(cancellationToken);

        Log.Information("[MEMBERSHIP-RELATION-REMOVED] By: {By}, Target: {Target}", 
            evt.MembershipId, evt.FriendMembershipId);

        return Result<ModifyFriendRelationResult, FriendFailure>.Ok(new ModifyFriendRelationResult
        {
            Outcome = "relation_removed"
        });
    }

    private async Task<Result<FriendshipStatusQueryRecord, FriendFailure>> GetFriendshipStatusAsync(
        EcliptixSchemaContext ctx,
        GetFriendshipStatusEvent evt,
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

        FriendshipStatusQueryRecord record = new()
        {
            Status = relation?.Status,
            InitiatorAccountId = relation?.InitiatorAccountId,
            Since = relation?.CreatedAt
        };

        return Result<FriendshipStatusQueryRecord, FriendFailure>.Ok(record);
    }

    private async Task<Result<ModifyFriendRelationResult, FriendFailure>> BlockUserAsync(
        EcliptixSchemaContext ctx,
        BlockUserEvent evt,
        CancellationToken cancellationToken)
    {
        if (evt.ByMembershipId == evt.TargetMembershipId)
        {
            return Result<ModifyFriendRelationResult, FriendFailure>.Err(
                FriendFailure.ValidationFailed("Cannot block yourself"));
        }

        MembershipRelationEntity? existing = await MembershipRelationQueries.GetMembershipRelation(
            ctx,
            evt.ByMembershipId,
            evt.TargetMembershipId,
            cancellationToken);

        if (existing != null)
        {
            if (existing.Status == MembershipRelationStatus.Blocked)
            {
                return Result<ModifyFriendRelationResult, FriendFailure>.Ok(new ModifyFriendRelationResult
                {
                    Outcome = "user_already_blocked"
                });
            }

            existing.Status = MembershipRelationStatus.Blocked;
            await ctx.SaveChangesAsync(cancellationToken);
        }
        else
        {
            long byAccountId = await ctx.Accounts
                .Where(a => a.Membership.UniqueId == evt.ByMembershipId)
                .Select(a => a.Id)
                .FirstOrDefaultAsync(cancellationToken);

            long targetAccountId = await ctx.Accounts
                .Where(a => a.Membership.UniqueId == evt.TargetMembershipId)
                .Select(a => a.Id)
                .FirstOrDefaultAsync(cancellationToken);

            if (byAccountId == 0 || targetAccountId == 0)
            {
                return Result<ModifyFriendRelationResult, FriendFailure>.Err(
                    FriendFailure.NotFound("Account not found"));
            }

            MembershipRelationEntity relation = new()
            {
                InitiatorAccountId = byAccountId,
                RecipientAccountId = targetAccountId,
                Status = MembershipRelationStatus.Blocked
            };

            ctx.MembershipRelations.Add(relation);
            await ctx.SaveChangesAsync(cancellationToken);
        }

        Log.Information("[USER-BLOCKED] By: {By}, Target: {Target}", 
            evt.ByMembershipId, evt.TargetMembershipId);

        return Result<ModifyFriendRelationResult, FriendFailure>.Ok(new ModifyFriendRelationResult
        {
            Outcome = "user_blocked"
        });
    }

    private async Task<Result<ModifyFriendRelationResult, FriendFailure>> UnblockUserAsync(
        EcliptixSchemaContext ctx,
        UnblockUserEvent evt,
        CancellationToken cancellationToken)
    {
        MembershipRelationEntity? relation = await MembershipRelationQueries.GetMembershipRelation(
            ctx,
            evt.ByMembershipId,
            evt.TargetMembershipId,
            cancellationToken);

        if (relation == null)
        {
            return Result<ModifyFriendRelationResult, FriendFailure>.Ok(new ModifyFriendRelationResult
            {
                Outcome = "user_not_blocked"
            });
        }

        if (relation.Status != MembershipRelationStatus.Blocked)
        {
            return Result<ModifyFriendRelationResult, FriendFailure>.Err(
                FriendFailure.ValidationFailed("User is not blocked"));
        }

        long byAccountId = await ctx.Accounts
            .Where(a => a.Membership.UniqueId == evt.ByMembershipId)
            .Select(a => a.Id)
            .FirstOrDefaultAsync(cancellationToken);

        if (byAccountId == 0)
        {
            return Result<ModifyFriendRelationResult, FriendFailure>.Err(
                FriendFailure.NotFound("Account not found"));
        }

        if (relation.InitiatorAccountId != byAccountId)
        {
            return Result<ModifyFriendRelationResult, FriendFailure>.Err(
                FriendFailure.ValidationFailed("Cannot unblock user you didn't block"));
        }

        ctx.MembershipRelations.Remove(relation);
        await ctx.SaveChangesAsync(cancellationToken);

        Log.Information("[USER-UNBLOCKED] By: {By}, Target: {Target}", 
            evt.ByMembershipId, evt.TargetMembershipId);

        return Result<ModifyFriendRelationResult, FriendFailure>.Ok(new ModifyFriendRelationResult
        {
            Outcome = "user_unblocked"
        });
    }

    protected override FriendFailure MapDbException(DbException ex)
    {
        return FriendFailure.DatabaseError($"Database error: {ex.Message}", ex);
    }

    protected override FriendFailure CreateTimeoutFailure(TimeoutException ex)
    {
        return FriendFailure.DatabaseError($"Operation timeout: {ex.Message}", ex);
    }

    protected override FriendFailure CreateGenericFailure(Exception ex)
    {
        return FriendFailure.UnexpectedError($"Unexpected error: {ex.Message}", ex);
    }
}

