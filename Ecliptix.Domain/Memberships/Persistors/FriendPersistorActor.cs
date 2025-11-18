using System.Data.Common;
using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents.Common;
using Ecliptix.Domain.Memberships.ActorEvents.Friend;
using Ecliptix.Domain.Memberships.Failures;
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
        ReceivePersistorCommand<SendFriendRequestEvent, FriendEntity>(
            SendFriendRequestAsync,
            "SendFriendRequest");

        ReceivePersistorCommand<AcceptFriendRequestEvent, Unit>(
            AcceptFriendRequestAsync,
            "AcceptFriendRequest");

        ReceivePersistorCommand<RejectFriendRequestEvent, Unit>(
            RejectFriendRequestAsync,
            "RejectFriendRequest");

        ReceivePersistorCommand<CancelFriendRequestEvent, Unit>(
            CancelFriendRequestAsync,
            "CancelFriendRequest");

        ReceivePersistorCommand<RemoveFriendEvent, Unit>(
            RemoveFriendAsync,
            "RemoveFriend");

        ReceivePersistorCommand<ListFriendsEvent, List<FriendEntity>>(
            ListFriendsAsync,
            "ListFriends");

        ReceivePersistorCommand<GetFriendshipStatusEvent, FriendEntity?>(
            GetFriendshipStatusAsync,
            "GetFriendshipStatus");
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

    private static (Guid, Guid) CanonicalPair(Guid a, Guid b)
    {
        return a.CompareTo(b) < 0 ? (a, b) : (b, a);
    }

    private async Task<Result<FriendEntity, FriendFailure>> SendFriendRequestAsync(
        EcliptixSchemaContext ctx,
        SendFriendRequestEvent evt,
        CancellationToken cancellationToken)
    {
        if (evt.FromMembershipId == evt.ToMembershipId)
        {
            return Result<FriendEntity, FriendFailure>.Err(
                FriendFailure.ValidationFailed("Cannot send friend request to yourself"));
        }

        (Guid ua, Guid ub) = CanonicalPair(evt.FromMembershipId, evt.ToMembershipId);

        FriendEntity? existing = await ctx.FriendRelations
            .FirstOrDefaultAsync(x => x.UserAId == ua && x.UserBId == ub && !x.IsDeleted, cancellationToken);

        if (existing != null)
        {
            if (existing.Status == FriendRelationStatus.Accepted)
            {
                return Result<FriendEntity, FriendFailure>.Err(
                    FriendFailure.AlreadyFriends());
            }

            if (existing.Status == FriendRelationStatus.Pending)
            {
                return Result<FriendEntity, FriendFailure>.Err(
                    FriendFailure.AlreadyRequested());
            }

            if (existing.Status == FriendRelationStatus.Blocked)
            {
                return Result<FriendEntity, FriendFailure>.Err(
                    FriendFailure.Blocked());
            }
        }

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

        Log.Information("[FRIEND-REQUEST-SENT] From: {From}, To: {To}", evt.FromMembershipId, evt.ToMembershipId);

        return Result<FriendEntity, FriendFailure>.Ok(relation);
    }

    private async Task<Result<Unit, FriendFailure>> AcceptFriendRequestAsync(
        EcliptixSchemaContext ctx,
        AcceptFriendRequestEvent evt,
        CancellationToken cancellationToken)
    {
        (Guid ua, Guid ub) = CanonicalPair(evt.ByMembershipId, evt.FromMembershipId);

        FriendEntity? relation = await ctx.FriendRelations
            .FirstOrDefaultAsync(x => x.UserAId == ua && x.UserBId == ub && !x.IsDeleted, cancellationToken);

        if (relation == null)
        {
            return Result<Unit, FriendFailure>.Err(FriendFailure.NotFound("Friend request not found"));
        }

        if (relation.Status != FriendRelationStatus.Pending)
        {
            return Result<Unit, FriendFailure>.Err(FriendFailure.ValidationFailed("Request is not pending"));
        }

        if (relation.RequestedById == evt.ByMembershipId)
        {
            return Result<Unit, FriendFailure>.Err(FriendFailure.ValidationFailed("Cannot accept own request"));
        }

        relation.Status = FriendRelationStatus.Accepted;
        relation.AcceptedAt = DateTimeOffset.UtcNow;
        await ctx.SaveChangesAsync(cancellationToken);

        Log.Information("[FRIEND-REQUEST-ACCEPTED] By: {By}, From: {From}", evt.ByMembershipId, evt.FromMembershipId);

        return Result<Unit, FriendFailure>.Ok(Unit.Value);
    }

    private async Task<Result<Unit, FriendFailure>> RejectFriendRequestAsync(
        EcliptixSchemaContext ctx,
        RejectFriendRequestEvent evt,
        CancellationToken cancellationToken)
    {
        (Guid ua, Guid ub) = CanonicalPair(evt.ByMembershipId, evt.FromMembershipId);

        FriendEntity? relation = await ctx.FriendRelations
            .FirstOrDefaultAsync(x => x.UserAId == ua && x.UserBId == ub && !x.IsDeleted, cancellationToken);

        if (relation == null)
        {
            return Result<Unit, FriendFailure>.Err(FriendFailure.NotFound("Friend request not found"));
        }

        if (relation.Status != FriendRelationStatus.Pending)
        {
            return Result<Unit, FriendFailure>.Err(FriendFailure.ValidationFailed("Request is not pending"));
        }

        relation.Status = FriendRelationStatus.Rejected;
        await ctx.SaveChangesAsync(cancellationToken);

        Log.Information("[FRIEND-REQUEST-REJECTED] By: {By}, From: {From}", evt.ByMembershipId, evt.FromMembershipId);

        return Result<Unit, FriendFailure>.Ok(Unit.Value);
    }

    private async Task<Result<Unit, FriendFailure>> CancelFriendRequestAsync(
        EcliptixSchemaContext ctx,
        CancelFriendRequestEvent evt,
        CancellationToken cancellationToken)
    {
        (Guid ua, Guid ub) = CanonicalPair(evt.FromMembershipId, evt.ToMembershipId);

        FriendEntity? relation = await ctx.FriendRelations
            .FirstOrDefaultAsync(x => x.UserAId == ua && x.UserBId == ub && !x.IsDeleted, cancellationToken);

        if (relation == null)
        {
            return Result<Unit, FriendFailure>.Err(FriendFailure.NotFound("Friend request not found"));
        }

        if (relation.Status != FriendRelationStatus.Pending)
        {
            return Result<Unit, FriendFailure>.Err(FriendFailure.ValidationFailed("Request is not pending"));
        }

        if (relation.RequestedById != evt.FromMembershipId)
        {
            return Result<Unit, FriendFailure>.Err(FriendFailure.ValidationFailed("Cannot cancel request sent by another user"));
        }

        ctx.FriendRelations.Remove(relation);
        await ctx.SaveChangesAsync(cancellationToken);

        Log.Information("[FRIEND-REQUEST-CANCELLED] From: {From}, To: {To}", evt.FromMembershipId, evt.ToMembershipId);

        return Result<Unit, FriendFailure>.Ok(Unit.Value);
    }

    private async Task<Result<Unit, FriendFailure>> RemoveFriendAsync(
        EcliptixSchemaContext ctx,
        RemoveFriendEvent evt,
        CancellationToken cancellationToken)
    {
        (Guid ua, Guid ub) = CanonicalPair(evt.MembershipId, evt.FriendMembershipId);

        FriendEntity? relation = await ctx.FriendRelations
            .FirstOrDefaultAsync(x => x.UserAId == ua && x.UserBId == ub && !x.IsDeleted, cancellationToken);

        if (relation == null)
        {
            return Result<Unit, FriendFailure>.Err(FriendFailure.NotFound("Friendship not found"));
        }

        if (relation.Status != FriendRelationStatus.Accepted)
        {
            return Result<Unit, FriendFailure>.Err(FriendFailure.ValidationFailed("Not friends"));
        }

        relation.Status = FriendRelationStatus.Removed;
        await ctx.SaveChangesAsync(cancellationToken);

        Log.Information("[FRIEND-REMOVED] By: {By}, Friend: {Friend}", evt.MembershipId, evt.FriendMembershipId);

        return Result<Unit, FriendFailure>.Ok(Unit.Value);
    }

    private async Task<Result<List<FriendEntity>, FriendFailure>> ListFriendsAsync(
        EcliptixSchemaContext ctx,
        ListFriendsEvent evt,
        CancellationToken cancellationToken)
    {
        int limit = Math.Max(1, Math.Min(100, evt.Limit));

        List<FriendEntity> friends = await ctx.FriendRelations
            .Where(x => (x.UserAId == evt.MembershipId || x.UserBId == evt.MembershipId) &&
                        x.Status == FriendRelationStatus.Accepted &&
                        !x.IsDeleted)
            .OrderByDescending(x => x.AcceptedAt)
            .Take(limit)
            .ToListAsync(cancellationToken);

        return Result<List<FriendEntity>, FriendFailure>.Ok(friends);
    }

    private async Task<Result<FriendEntity?, FriendFailure>> GetFriendshipStatusAsync(
        EcliptixSchemaContext ctx,
        GetFriendshipStatusEvent evt,
        CancellationToken cancellationToken)
    {
        (Guid ua, Guid ub) = CanonicalPair(evt.MembershipId, evt.OtherMembershipId);

        FriendEntity? relation = await ctx.FriendRelations
            .FirstOrDefaultAsync(x => x.UserAId == ua && x.UserBId == ub && !x.IsDeleted, cancellationToken);

        return Result<FriendEntity?, FriendFailure>.Ok(relation);
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

