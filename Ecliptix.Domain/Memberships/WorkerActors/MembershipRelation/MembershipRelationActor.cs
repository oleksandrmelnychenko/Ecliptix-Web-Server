using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents.Friend;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.QueryResults;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Protobuf.Friend;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Configuration;
using Serilog;
using DomainFriendFailure = Ecliptix.Domain.Memberships.Failures.FriendFailure;
using DomainFriendFailureType = Ecliptix.Domain.Memberships.Failures.FriendFailureType;

namespace Ecliptix.Domain.Memberships.WorkerActors.MembershipRelation;

public sealed class MembershipRelationActor : ReceiveActor
{
    private readonly IActorRef _membershipRelationPersistor;

    public MembershipRelationActor(IActorRef membershipRelationPersistor)
    {
        _membershipRelationPersistor = membershipRelationPersistor;

        ReceiveAsync<RemoveFriendEvent>(HandleRemoveFriend);
        ReceiveAsync<GetFriendshipStatusEvent>(HandleGetFriendshipStatus);
        ReceiveAsync<BlockUserEvent>(HandleBlockUser);
        ReceiveAsync<UnblockUserEvent>(HandleUnblockUser);
    }

    public static Props Build(IActorRef membershipRelationPersistor)
    {
        return Props.Create(() => new MembershipRelationActor(membershipRelationPersistor));
    }

    private async Task HandleRemoveFriend(RemoveFriendEvent evt)
    {
        IActorRef replyTo = Sender;

        try
        {
            Task<Result<ModifyFriendRelationResult, DomainFriendFailure>> task =
                _membershipRelationPersistor.Ask<Result<ModifyFriendRelationResult, DomainFriendFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<ModifyFriendRelationResult, DomainFriendFailure> result = await task;

            Result<GenericResponse, DomainFriendFailure> response = result.Match(
                ok: _ => Result<GenericResponse, DomainFriendFailure>.Ok(new GenericResponse { Ok = true }),
                err: failure =>
                {
                    if (failure.IsUserFacing)
                    {
                        return Result<GenericResponse, DomainFriendFailure>.Ok(
                            new GenericResponse { Ok = false, Message = failure.Message });
                    }

                    return Result<GenericResponse, DomainFriendFailure>.Err(failure);
                }
            );

            replyTo.Tell(response);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[MEMBERSHIP-RELATION-ACTOR] Error handling RemoveFriend");
            replyTo.Tell(Result<GenericResponse, DomainFriendFailure>.Err(
                DomainFriendFailure.UnexpectedError("Failed to remove friend", ex)));
        }
    }

    private async Task HandleGetFriendshipStatus(GetFriendshipStatusEvent evt)
    {
        IActorRef replyTo = Sender;

        try
        {
            Task<Result<FriendshipStatusQueryRecord, DomainFriendFailure>> task =
                _membershipRelationPersistor.Ask<Result<FriendshipStatusQueryRecord, DomainFriendFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<FriendshipStatusQueryRecord, DomainFriendFailure> result = await task;

            Result<GetFriendshipStatusResponse, DomainFriendFailure> response = result.Match(
                ok: record =>
                {
                    if (record.Status == null)
                    {
                        return Result<GetFriendshipStatusResponse, DomainFriendFailure>.Ok(
                            new GetFriendshipStatusResponse
                            {
                                Status = FriendshipStatus.None
                            });
                    }

                    FriendshipStatus status = record.Status.Value switch
                    {
                        MembershipRelationStatus.Blocked => FriendshipStatus.Blocked,
                        MembershipRelationStatus.Removed => FriendshipStatus.None,
                        _ => FriendshipStatus.None
                    };

                    GetFriendshipStatusResponse statusResponse = new()
                    {
                        Status = status
                    };

                    if (record.Since.HasValue)
                    {
                        statusResponse.Since = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTimeOffset(
                            record.Since.Value);
                    }

                    return Result<GetFriendshipStatusResponse, DomainFriendFailure>.Ok(statusResponse);
                },
                err: failure => Result<GetFriendshipStatusResponse, DomainFriendFailure>.Err(failure)
            );

            replyTo.Tell(response);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[MEMBERSHIP-RELATION-ACTOR] Error handling GetFriendshipStatus");
            replyTo.Tell(Result<GetFriendshipStatusResponse, DomainFriendFailure>.Err(
                DomainFriendFailure.UnexpectedError("Failed to get friendship status", ex)));
        }
    }

    private async Task HandleBlockUser(BlockUserEvent evt)
    {
        IActorRef replyTo = Sender;

        try
        {
            Task<Result<ModifyFriendRelationResult, DomainFriendFailure>> task =
                _membershipRelationPersistor.Ask<Result<ModifyFriendRelationResult, DomainFriendFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<ModifyFriendRelationResult, DomainFriendFailure> result = await task;

            Result<GenericResponse, DomainFriendFailure> response = result.Match(
                ok: _ => Result<GenericResponse, DomainFriendFailure>.Ok(new GenericResponse { Ok = true }),
                err: failure =>
                {
                    if (failure.IsUserFacing)
                    {
                        return Result<GenericResponse, DomainFriendFailure>.Ok(
                            new GenericResponse { Ok = false, Message = failure.Message });
                    }

                    return Result<GenericResponse, DomainFriendFailure>.Err(failure);
                }
            );

            replyTo.Tell(response);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[MEMBERSHIP-RELATION-ACTOR] Error handling BlockUser");
            replyTo.Tell(Result<GenericResponse, DomainFriendFailure>.Err(
                DomainFriendFailure.UnexpectedError("Failed to block user", ex)));
        }
    }

    private async Task HandleUnblockUser(UnblockUserEvent evt)
    {
        IActorRef replyTo = Sender;

        try
        {
            Task<Result<ModifyFriendRelationResult, DomainFriendFailure>> task =
                _membershipRelationPersistor.Ask<Result<ModifyFriendRelationResult, DomainFriendFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<ModifyFriendRelationResult, DomainFriendFailure> result = await task;

            Result<GenericResponse, DomainFriendFailure> response = result.Match(
                ok: _ => Result<GenericResponse, DomainFriendFailure>.Ok(new GenericResponse { Ok = true }),
                err: failure =>
                {
                    if (failure.IsUserFacing)
                    {
                        return Result<GenericResponse, DomainFriendFailure>.Ok(
                            new GenericResponse { Ok = false, Message = failure.Message });
                    }

                    return Result<GenericResponse, DomainFriendFailure>.Err(failure);
                }
            );

            replyTo.Tell(response);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[MEMBERSHIP-RELATION-ACTOR] Error handling UnblockUser");
            replyTo.Tell(Result<GenericResponse, DomainFriendFailure>.Err(
                DomainFriendFailure.UnexpectedError("Failed to unblock user", ex)));
        }
    }

    private static FriendFailureType MapToProtoFailureType(DomainFriendFailureType domainType)
    {
        return domainType switch
        {
            DomainFriendFailureType.NotFound => FriendFailureType.FriendNotFound,
            DomainFriendFailureType.Blocked => FriendFailureType.FriendBlocked,
            DomainFriendFailureType.InvalidRequest => FriendFailureType.FriendInvalidRequest,
            DomainFriendFailureType.Validation => FriendFailureType.FriendValidationFailed,
            DomainFriendFailureType.Unauthorized => FriendFailureType.FriendNotAuthorized,
            DomainFriendFailureType.ConcurrencyConflict => FriendFailureType.FriendConcurrencyConflict,
            DomainFriendFailureType.PersistorAccess => FriendFailureType.FriendPersistorAccess,
            DomainFriendFailureType.DatabaseError => FriendFailureType.FriendDatabaseError,
            _ => FriendFailureType.FriendInternal
        };
    }
}

