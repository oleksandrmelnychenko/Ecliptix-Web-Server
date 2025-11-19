using System.Data.Common;
using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents.Common;
using Ecliptix.Domain.Memberships.ActorEvents.Friend;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.CompiledQueries;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.QueryResults;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Utilities;
using Microsoft.EntityFrameworkCore;
using Serilog;

namespace Ecliptix.Domain.Memberships.Persistors;

public class FriendPersistorActor : PersistorBase<FriendFailure>
{
    public FriendPersistorActor(IDbContextFactory<EcliptixSchemaContext> dbContextFactory)
        : base(dbContextFactory)
    {
        Become(Ready);
    }

    public static Props Build(IDbContextFactory<EcliptixSchemaContext> dbContextFactory)
    {
        return Props.Create(() => new FriendPersistorActor(dbContextFactory));
    }

    private void Ready()
    {
        RegisterHandlers();
    }

    private void RegisterHandlers()
    {
        ReceivePersistorCommand<SendFriendRequestEvent, SendFriendRequestResult>(
            SendFriendRequestAsync,
            "SendFriendRequest");

        ReceivePersistorCommand<AcceptFriendRequestEvent, ModifyFriendRelationResult>(
            AcceptFriendRequestAsync,
            "AcceptFriendRequest");

        ReceivePersistorCommand<RejectFriendRequestEvent, ModifyFriendRelationResult>(
            RejectFriendRequestAsync,
            "RejectFriendRequest");

        ReceivePersistorCommand<CancelFriendRequestEvent, ModifyFriendRelationResult>(
            CancelFriendRequestAsync,
            "CancelFriendRequest");

        ReceivePersistorCommand<RemoveFriendEvent, ModifyFriendRelationResult>(
            RemoveFriendAsync,
            "RemoveFriend");

        ReceivePersistorCommand<ListFriendsEvent, List<FriendQueryRecord>>(
            ListFriendsAsync,
            "ListFriends");

        ReceivePersistorCommand<GetFriendshipStatusEvent, FriendshipStatusQueryRecord>(
            GetFriendshipStatusAsync,
            "GetFriendshipStatus");

        ReceivePersistorCommand<BlockUserEvent, ModifyFriendRelationResult>(
            BlockUserAsync,
            "BlockUser");

        ReceivePersistorCommand<UnblockUserEvent, ModifyFriendRelationResult>(
            UnblockUserAsync,
            "UnblockUser");

        ReceivePersistorCommand<ListPendingRequestsEvent, List<PendingRequestQueryRecord>>(
            ListPendingRequestsAsync,
            "ListPendingRequests");
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

    private async Task<Result<SendFriendRequestResult, FriendFailure>> SendFriendRequestAsync(
        EcliptixSchemaContext ctx,
        SendFriendRequestEvent evt,
        CancellationToken cancellationToken)
    {
        if (evt.FromMembershipId == evt.ToMembershipId)
        {
            return Result<SendFriendRequestResult, FriendFailure>.Err(
                FriendFailure.CannotFriendYourself());
        }

        FriendEntity? existing = await FriendQueries.GetFriendRelation(
            ctx,
            evt.FromMembershipId,
            evt.ToMembershipId,
            cancellationToken);

        if (existing != null)
        {
            if (existing.Status == FriendRelationStatus.Accepted)
            {
                return Result<SendFriendRequestResult, FriendFailure>.Err(
                    FriendFailure.AlreadyFriends());
            }

            if (existing.Status == FriendRelationStatus.Pending)
            {
                return Result<SendFriendRequestResult, FriendFailure>.Err(
                    FriendFailure.AlreadyRequested());
            }

            if (existing.Status == FriendRelationStatus.Blocked)
            {
                return Result<SendFriendRequestResult, FriendFailure>.Err(
                    FriendFailure.Blocked());
            }
        }

        (Guid ua, Guid ub) = evt.FromMembershipId.CompareTo(evt.ToMembershipId) < 0
            ? (evt.FromMembershipId, evt.ToMembershipId)
            : (evt.ToMembershipId, evt.FromMembershipId);

        FriendEntity relation = new()
        {
            UserAId = ua,
            UserBId = ub,
            RequestedById = evt.FromMembershipId,
            Status = FriendRelationStatus.Pending,
            Message = evt.Message
        };

        ctx.FriendRelations.Add(relation);
        await ctx.SaveChangesAsync(cancellationToken);

        Log.Information("[FRIEND-REQUEST-SENT] From: {From}, To: {To}", 
            evt.FromMembershipId, evt.ToMembershipId);

        return Result<SendFriendRequestResult, FriendFailure>.Ok(new SendFriendRequestResult
        {
            RelationId = relation.UniqueId,
            Outcome = "friend_request_sent"
        });
    }

    private async Task<Result<ModifyFriendRelationResult, FriendFailure>> AcceptFriendRequestAsync(
        EcliptixSchemaContext ctx,
        AcceptFriendRequestEvent evt,
        CancellationToken cancellationToken)
    {
        FriendEntity? relation = await FriendQueries.GetFriendRelation(
            ctx,
            evt.ByMembershipId,
            evt.FromMembershipId,
            cancellationToken);

        if (relation == null)
        {
            return Result<ModifyFriendRelationResult, FriendFailure>.Err(
                FriendFailure.FriendRequestNotFound());
        }

        if (relation.Status != FriendRelationStatus.Pending)
        {
            return Result<ModifyFriendRelationResult, FriendFailure>.Err(
                FriendFailure.RequestNotPending());
        }

        if (relation.RequestedById == evt.ByMembershipId)
        {
            return Result<ModifyFriendRelationResult, FriendFailure>.Err(
                FriendFailure.CannotAcceptOwnRequest());
        }

        relation.Status = FriendRelationStatus.Accepted;
        relation.AcceptedAt = DateTimeOffset.UtcNow;
        await ctx.SaveChangesAsync(cancellationToken);

        Log.Information("[FRIEND-REQUEST-ACCEPTED] By: {By}, From: {From}", 
            evt.ByMembershipId, evt.FromMembershipId);

        return Result<ModifyFriendRelationResult, FriendFailure>.Ok(new ModifyFriendRelationResult
        {
            Outcome = "friend_request_accepted"
        });
    }

    private async Task<Result<ModifyFriendRelationResult, FriendFailure>> RejectFriendRequestAsync(
        EcliptixSchemaContext ctx,
        RejectFriendRequestEvent evt,
        CancellationToken cancellationToken)
    {
        FriendEntity? relation = await FriendQueries.GetFriendRelation(
            ctx,
            evt.ByMembershipId,
            evt.FromMembershipId,
            cancellationToken);

        if (relation == null)
        {
            return Result<ModifyFriendRelationResult, FriendFailure>.Err(
                FriendFailure.FriendRequestNotFound());
        }

        if (relation.Status != FriendRelationStatus.Pending)
        {
            return Result<ModifyFriendRelationResult, FriendFailure>.Err(
                FriendFailure.RequestNotPending());
        }

        relation.Status = FriendRelationStatus.Rejected;
        await ctx.SaveChangesAsync(cancellationToken);

        Log.Information("[FRIEND-REQUEST-REJECTED] By: {By}, From: {From}", 
            evt.ByMembershipId, evt.FromMembershipId);

        return Result<ModifyFriendRelationResult, FriendFailure>.Ok(new ModifyFriendRelationResult
        {
            Outcome = "friend_request_rejected"
        });
    }

    private async Task<Result<ModifyFriendRelationResult, FriendFailure>> CancelFriendRequestAsync(
        EcliptixSchemaContext ctx,
        CancelFriendRequestEvent evt,
        CancellationToken cancellationToken)
    {
        FriendEntity? relation = await FriendQueries.GetFriendRelation(
            ctx,
            evt.FromMembershipId,
            evt.ToMembershipId,
            cancellationToken);

        if (relation == null)
        {
            return Result<ModifyFriendRelationResult, FriendFailure>.Err(
                FriendFailure.FriendRequestNotFound());
        }

        if (relation.Status != FriendRelationStatus.Pending)
        {
            return Result<ModifyFriendRelationResult, FriendFailure>.Err(
                FriendFailure.RequestNotPending());
        }

        if (relation.RequestedById != evt.FromMembershipId)
        {
            return Result<ModifyFriendRelationResult, FriendFailure>.Err(
                FriendFailure.CannotCancelOtherRequest());
        }

        ctx.FriendRelations.Remove(relation);
        await ctx.SaveChangesAsync(cancellationToken);

        Log.Information("[FRIEND-REQUEST-CANCELLED] From: {From}, To: {To}", 
            evt.FromMembershipId, evt.ToMembershipId);

        return Result<ModifyFriendRelationResult, FriendFailure>.Ok(new ModifyFriendRelationResult
        {
            Outcome = "friend_request_cancelled"
        });
    }

    private async Task<Result<ModifyFriendRelationResult, FriendFailure>> RemoveFriendAsync(
        EcliptixSchemaContext ctx,
        RemoveFriendEvent evt,
        CancellationToken cancellationToken)
    {
        FriendEntity? relation = await FriendQueries.GetFriendRelation(
            ctx,
            evt.MembershipId,
            evt.FriendMembershipId,
            cancellationToken);

        if (relation == null)
        {
            return Result<ModifyFriendRelationResult, FriendFailure>.Err(
                FriendFailure.FriendRelationNotFound());
        }

        if (relation.Status != FriendRelationStatus.Accepted)
        {
            return Result<ModifyFriendRelationResult, FriendFailure>.Err(
                FriendFailure.NotFriends());
        }

        relation.Status = FriendRelationStatus.Removed;
        await ctx.SaveChangesAsync(cancellationToken);

        Log.Information("[FRIEND-REMOVED] By: {By}, Friend: {Friend}", 
            evt.MembershipId, evt.FriendMembershipId);

        return Result<ModifyFriendRelationResult, FriendFailure>.Ok(new ModifyFriendRelationResult
        {
            Outcome = "friend_removed"
        });
    }

    private async Task<Result<List<FriendQueryRecord>, FriendFailure>> ListFriendsAsync(
        EcliptixSchemaContext ctx,
        ListFriendsEvent evt,
        CancellationToken cancellationToken)
    {
        int limit = Math.Max(1, Math.Min(100, evt.Limit));

        List<FriendEntity> friends = await FriendQueries.GetFriendsList(
            ctx,
            evt.MembershipId,
            limit,
            cancellationToken);

        List<FriendQueryRecord> records = friends.Select(f => new FriendQueryRecord
        {
            MembershipId = f.OtherUserId(evt.MembershipId),
            Since = f.AcceptedAt
        }).ToList();

        return Result<List<FriendQueryRecord>, FriendFailure>.Ok(records);
    }

    private async Task<Result<FriendshipStatusQueryRecord, FriendFailure>> GetFriendshipStatusAsync(
        EcliptixSchemaContext ctx,
        GetFriendshipStatusEvent evt,
        CancellationToken cancellationToken)
    {
        FriendEntity? relation = await FriendQueries.GetFriendRelation(
            ctx,
            evt.MembershipId,
            evt.OtherMembershipId,
            cancellationToken);

        FriendshipStatusQueryRecord record = new()
        {
            Status = relation?.Status,
            RequestedById = relation?.RequestedById,
            Since = relation?.AcceptedAt ?? relation?.CreatedAt
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

        FriendEntity? existing = await FriendQueries.GetFriendRelation(
            ctx,
            evt.ByMembershipId,
            evt.TargetMembershipId,
            cancellationToken);

        if (existing != null)
        {
            if (existing.Status == FriendRelationStatus.Blocked)
            {
                return Result<ModifyFriendRelationResult, FriendFailure>.Ok(new ModifyFriendRelationResult
                {
                    Outcome = "user_already_blocked"
                });
            }

            existing.Status = FriendRelationStatus.Blocked;
            existing.RequestedById = evt.ByMembershipId;
            await ctx.SaveChangesAsync(cancellationToken);
        }
        else
        {
            (Guid ua, Guid ub) = evt.ByMembershipId.CompareTo(evt.TargetMembershipId) < 0
                ? (evt.ByMembershipId, evt.TargetMembershipId)
                : (evt.TargetMembershipId, evt.ByMembershipId);

            FriendEntity relation = new()
            {
                UserAId = ua,
                UserBId = ub,
                RequestedById = evt.ByMembershipId,
                Status = FriendRelationStatus.Blocked
            };

            ctx.FriendRelations.Add(relation);
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
        FriendEntity? relation = await FriendQueries.GetFriendRelation(
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

        if (relation.Status != FriendRelationStatus.Blocked)
        {
            return Result<ModifyFriendRelationResult, FriendFailure>.Err(
                FriendFailure.ValidationFailed("User is not blocked"));
        }

        if (relation.RequestedById != evt.ByMembershipId)
        {
            return Result<ModifyFriendRelationResult, FriendFailure>.Err(
                FriendFailure.ValidationFailed("Cannot unblock user you didn't block"));
        }

        ctx.FriendRelations.Remove(relation);
        await ctx.SaveChangesAsync(cancellationToken);

        Log.Information("[USER-UNBLOCKED] By: {By}, Target: {Target}", 
            evt.ByMembershipId, evt.TargetMembershipId);

        return Result<ModifyFriendRelationResult, FriendFailure>.Ok(new ModifyFriendRelationResult
        {
            Outcome = "user_unblocked"
        });
    }

    private async Task<Result<List<PendingRequestQueryRecord>, FriendFailure>> ListPendingRequestsAsync(
        EcliptixSchemaContext ctx,
        ListPendingRequestsEvent evt,
        CancellationToken cancellationToken)
    {
        int limit = Math.Max(1, Math.Min(100, evt.Limit));

        List<FriendEntity> requests = evt.IsIncoming
            ? await FriendQueries.GetPendingRequestsIncoming(ctx, evt.MembershipId, limit, cancellationToken)
            : await FriendQueries.GetPendingRequestsOutgoing(ctx, evt.MembershipId, limit, cancellationToken);

        List<PendingRequestQueryRecord> records = requests.Select(r => new PendingRequestQueryRecord
        {
            MembershipId = r.OtherUserId(evt.MembershipId),
            RequestedAt = r.CreatedAt,
            Message = r.Message
        }).ToList();

        return Result<List<PendingRequestQueryRecord>, FriendFailure>.Ok(records);
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

