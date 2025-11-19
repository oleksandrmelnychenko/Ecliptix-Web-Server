using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents.Friend;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.QueryResults;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Protobuf.Friend;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Configuration;
using Serilog;

namespace Ecliptix.Domain.Memberships.WorkerActors.Friend;

public sealed class FriendActor : ReceiveActor
{
    private readonly IActorRef _friendPersistor;

    public FriendActor(IActorRef friendPersistor)
    {
        _friendPersistor = friendPersistor;

        ReceiveAsync<SendFriendRequestEvent>(HandleSendFriendRequest);
        ReceiveAsync<AcceptFriendRequestEvent>(HandleAcceptFriendRequest);
        ReceiveAsync<RejectFriendRequestEvent>(HandleRejectFriendRequest);
        ReceiveAsync<CancelFriendRequestEvent>(HandleCancelFriendRequest);
        ReceiveAsync<RemoveFriendEvent>(HandleRemoveFriend);
        ReceiveAsync<ListFriendsEvent>(HandleListFriends);
        ReceiveAsync<GetFriendshipStatusEvent>(HandleGetFriendshipStatus);
        ReceiveAsync<BlockUserEvent>(HandleBlockUser);
        ReceiveAsync<UnblockUserEvent>(HandleUnblockUser);
        ReceiveAsync<ListPendingRequestsEvent>(HandleListPendingRequests);
    }

    public static Props Build(IActorRef friendPersistor)
    {
        return Props.Create(() => new FriendActor(friendPersistor));
    }

    private async Task HandleSendFriendRequest(SendFriendRequestEvent evt)
    {
        IActorRef replyTo = Sender;

        try
        {
            Task<Result<SendFriendRequestResult, FriendFailure>> task =
                _friendPersistor.Ask<Result<SendFriendRequestResult, FriendFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<SendFriendRequestResult, FriendFailure> result = await task;

            Result<SendFriendRequestResponse, FriendFailure> response = result.Match(
                ok: _ => Result<SendFriendRequestResponse, FriendFailure>.Ok(
                    new SendFriendRequestResponse
                    {
                        Result = SendFriendRequestResponse.Types.Result.Succeeded
                    }),
                err: failure =>
                {
                    SendFriendRequestResponse.Types.Result resultType = failure.FailureType switch
                    {
                        FriendFailureType.AlreadyRequested => SendFriendRequestResponse.Types.Result.AlreadyRequested,
                        FriendFailureType.AlreadyFriends => SendFriendRequestResponse.Types.Result.AlreadyFriends,
                        FriendFailureType.Blocked => SendFriendRequestResponse.Types.Result.Blocked,
                        _ => SendFriendRequestResponse.Types.Result.Failed
                    };

                    if (failure.IsUserFacing)
                    {
                        return Result<SendFriendRequestResponse, FriendFailure>.Ok(
                            new SendFriendRequestResponse
                            {
                                Result = resultType,
                                Message = failure.Message
                            });
                    }

                    return Result<SendFriendRequestResponse, FriendFailure>.Err(failure);
                }
            );

            replyTo.Tell(response);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[FRIEND-ACTOR] Error handling SendFriendRequest");
            replyTo.Tell(Result<SendFriendRequestResponse, FriendFailure>.Err(
                FriendFailure.UnexpectedError("Failed to send friend request", ex)));
        }
    }

    private async Task HandleAcceptFriendRequest(AcceptFriendRequestEvent evt)
    {
        IActorRef replyTo = Sender;

        try
        {
            Task<Result<ModifyFriendRelationResult, FriendFailure>> task =
                _friendPersistor.Ask<Result<ModifyFriendRelationResult, FriendFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<ModifyFriendRelationResult, FriendFailure> result = await task;

            Result<GenericResponse, FriendFailure> response = result.Match(
                ok: _ => Result<GenericResponse, FriendFailure>.Ok(
                    new GenericResponse { Ok = true }),
                err: failure =>
                {
                    if (failure.IsUserFacing)
                    {
                        return Result<GenericResponse, FriendFailure>.Ok(
                            new GenericResponse
                            {
                                Ok = false,
                                Message = failure.Message
                            });
                    }

                    return Result<GenericResponse, FriendFailure>.Err(failure);
                }
            );

            replyTo.Tell(response);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[FRIEND-ACTOR] Error handling AcceptFriendRequest");
            replyTo.Tell(Result<GenericResponse, FriendFailure>.Err(
                FriendFailure.UnexpectedError("Failed to accept friend request", ex)));
        }
    }

    private async Task HandleRejectFriendRequest(RejectFriendRequestEvent evt)
    {
        IActorRef replyTo = Sender;

        try
        {
            Task<Result<ModifyFriendRelationResult, FriendFailure>> task =
                _friendPersistor.Ask<Result<ModifyFriendRelationResult, FriendFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<ModifyFriendRelationResult, FriendFailure> result = await task;

            Result<GenericResponse, FriendFailure> response = result.Match(
                ok: _ => Result<GenericResponse, FriendFailure>.Ok(new GenericResponse { Ok = true }),
                err: failure =>
                {
                    if (failure.IsUserFacing)
                    {
                        return Result<GenericResponse, FriendFailure>.Ok(
                            new GenericResponse { Ok = false, Message = failure.Message });
                    }

                    return Result<GenericResponse, FriendFailure>.Err(failure);
                }
            );

            replyTo.Tell(response);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[FRIEND-ACTOR] Error handling RejectFriendRequest");
            replyTo.Tell(Result<GenericResponse, FriendFailure>.Err(
                FriendFailure.UnexpectedError("Failed to reject friend request", ex)));
        }
    }

    private async Task HandleCancelFriendRequest(CancelFriendRequestEvent evt)
    {
        IActorRef replyTo = Sender;

        try
        {
            Task<Result<ModifyFriendRelationResult, FriendFailure>> task =
                _friendPersistor.Ask<Result<ModifyFriendRelationResult, FriendFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<ModifyFriendRelationResult, FriendFailure> result = await task;

            Result<GenericResponse, FriendFailure> response = result.Match(
                ok: _ => Result<GenericResponse, FriendFailure>.Ok(new GenericResponse { Ok = true }),
                err: failure =>
                {
                    if (failure.IsUserFacing)
                    {
                        return Result<GenericResponse, FriendFailure>.Ok(
                            new GenericResponse { Ok = false, Message = failure.Message });
                    }

                    return Result<GenericResponse, FriendFailure>.Err(failure);
                }
            );

            replyTo.Tell(response);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[FRIEND-ACTOR] Error handling CancelFriendRequest");
            replyTo.Tell(Result<GenericResponse, FriendFailure>.Err(
                FriendFailure.UnexpectedError("Failed to cancel friend request", ex)));
        }
    }

    private async Task HandleRemoveFriend(RemoveFriendEvent evt)
    {
        IActorRef replyTo = Sender;

        try
        {
            Task<Result<ModifyFriendRelationResult, FriendFailure>> task =
                _friendPersistor.Ask<Result<ModifyFriendRelationResult, FriendFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<ModifyFriendRelationResult, FriendFailure> result = await task;

            Result<GenericResponse, FriendFailure> response = result.Match(
                ok: _ => Result<GenericResponse, FriendFailure>.Ok(new GenericResponse { Ok = true }),
                err: failure =>
                {
                    if (failure.IsUserFacing)
                    {
                        return Result<GenericResponse, FriendFailure>.Ok(
                            new GenericResponse { Ok = false, Message = failure.Message });
                    }

                    return Result<GenericResponse, FriendFailure>.Err(failure);
                }
            );

            replyTo.Tell(response);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[FRIEND-ACTOR] Error handling RemoveFriend");
            replyTo.Tell(Result<GenericResponse, FriendFailure>.Err(
                FriendFailure.UnexpectedError("Failed to remove friend", ex)));
        }
    }

    private async Task HandleListFriends(ListFriendsEvent evt)
    {
        IActorRef replyTo = Sender;

        try
        {
            Task<Result<List<FriendQueryRecord>, FriendFailure>> task =
                _friendPersistor.Ask<Result<List<FriendQueryRecord>, FriendFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<List<FriendQueryRecord>, FriendFailure> result = await task;

            Result<ListFriendsResponse, FriendFailure> response = result.Match(
                ok: friends =>
                {
                    ListFriendsResponse listResponse = new();
                    foreach (FriendQueryRecord f in friends)
                    {
                        listResponse.Friends.Add(new Ecliptix.Protobuf.Friend.Friend
                        {
                            MembershipId = Google.Protobuf.ByteString.CopyFrom(f.MembershipId.ToByteArray()),
                            Since = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTimeOffset(
                                f.Since ?? DateTimeOffset.UtcNow)
                        });
                    }

                    return Result<ListFriendsResponse, FriendFailure>.Ok(listResponse);
                },
                err: failure => Result<ListFriendsResponse, FriendFailure>.Err(failure)
            );

            replyTo.Tell(response);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[FRIEND-ACTOR] Error handling ListFriends");
            replyTo.Tell(Result<ListFriendsResponse, FriendFailure>.Err(
                FriendFailure.UnexpectedError("Failed to list friends", ex)));
        }
    }

    private async Task HandleGetFriendshipStatus(GetFriendshipStatusEvent evt)
    {
        IActorRef replyTo = Sender;

        try
        {
            Task<Result<FriendshipStatusQueryRecord, FriendFailure>> task =
                _friendPersistor.Ask<Result<FriendshipStatusQueryRecord, FriendFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<FriendshipStatusQueryRecord, FriendFailure> result = await task;

            Result<GetFriendshipStatusResponse, FriendFailure> response = result.Match(
                ok: record =>
                {
                    if (record.Status == null)
                    {
                        return Result<GetFriendshipStatusResponse, FriendFailure>.Ok(
                            new GetFriendshipStatusResponse
                            {
                                Status = FriendshipStatus.None
                            });
                    }

                    FriendshipStatus status = record.Status.Value switch
                    {
                        FriendRelationStatus.Pending when record.RequestedById == evt.MembershipId =>
                            FriendshipStatus.PendingOutgoing,
                        FriendRelationStatus.Pending => FriendshipStatus.PendingIncoming,
                        FriendRelationStatus.Accepted => FriendshipStatus.Accepted,
                        FriendRelationStatus.Blocked when record.RequestedById == evt.MembershipId =>
                            FriendshipStatus.Blocked,
                        FriendRelationStatus.Blocked => FriendshipStatus.BlockedBy,
                        FriendRelationStatus.Rejected => FriendshipStatus.Rejected,
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

                    return Result<GetFriendshipStatusResponse, FriendFailure>.Ok(statusResponse);
                },
                err: failure => Result<GetFriendshipStatusResponse, FriendFailure>.Err(failure)
            );

            replyTo.Tell(response);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[FRIEND-ACTOR] Error handling GetFriendshipStatus");
            replyTo.Tell(Result<GetFriendshipStatusResponse, FriendFailure>.Err(
                FriendFailure.UnexpectedError("Failed to get friendship status", ex)));
        }
    }

    private async Task HandleBlockUser(BlockUserEvent evt)
    {
        IActorRef replyTo = Sender;

        try
        {
            Task<Result<ModifyFriendRelationResult, FriendFailure>> task =
                _friendPersistor.Ask<Result<ModifyFriendRelationResult, FriendFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<ModifyFriendRelationResult, FriendFailure> result = await task;

            Result<GenericResponse, FriendFailure> response = result.Match(
                ok: _ => Result<GenericResponse, FriendFailure>.Ok(new GenericResponse { Ok = true }),
                err: failure =>
                {
                    if (failure.IsUserFacing)
                    {
                        return Result<GenericResponse, FriendFailure>.Ok(
                            new GenericResponse { Ok = false, Message = failure.Message });
                    }

                    return Result<GenericResponse, FriendFailure>.Err(failure);
                }
            );

            replyTo.Tell(response);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[FRIEND-ACTOR] Error handling BlockUser");
            replyTo.Tell(Result<GenericResponse, FriendFailure>.Err(
                FriendFailure.UnexpectedError("Failed to block user", ex)));
        }
    }

    private async Task HandleUnblockUser(UnblockUserEvent evt)
    {
        IActorRef replyTo = Sender;

        try
        {
            Task<Result<ModifyFriendRelationResult, FriendFailure>> task =
                _friendPersistor.Ask<Result<ModifyFriendRelationResult, FriendFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<ModifyFriendRelationResult, FriendFailure> result = await task;

            Result<GenericResponse, FriendFailure> response = result.Match(
                ok: _ => Result<GenericResponse, FriendFailure>.Ok(new GenericResponse { Ok = true }),
                err: failure =>
                {
                    if (failure.IsUserFacing)
                    {
                        return Result<GenericResponse, FriendFailure>.Ok(
                            new GenericResponse { Ok = false, Message = failure.Message });
                    }

                    return Result<GenericResponse, FriendFailure>.Err(failure);
                }
            );

            replyTo.Tell(response);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[FRIEND-ACTOR] Error handling UnblockUser");
            replyTo.Tell(Result<GenericResponse, FriendFailure>.Err(
                FriendFailure.UnexpectedError("Failed to unblock user", ex)));
        }
    }

    private async Task HandleListPendingRequests(ListPendingRequestsEvent evt)
    {
        IActorRef replyTo = Sender;

        try
        {
            Task<Result<List<PendingRequestQueryRecord>, FriendFailure>> task =
                _friendPersistor.Ask<Result<List<PendingRequestQueryRecord>, FriendFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<List<PendingRequestQueryRecord>, FriendFailure> result = await task;

            Result<ListPendingRequestsResponse, FriendFailure> response = result.Match(
                ok: requests =>
                {
                    ListPendingRequestsResponse listResponse = new();
                    foreach (PendingRequestQueryRecord r in requests)
                    {
                        listResponse.Requests.Add(new PendingRequest
                        {
                            MembershipId = Google.Protobuf.ByteString.CopyFrom((ReadOnlySpan<byte>)r.MembershipId.ToByteArray()),
                            RequestedAt = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTimeOffset(r.RequestedAt),
                            Message = r.Message ?? string.Empty
                        });
                    }

                    return Result<ListPendingRequestsResponse, FriendFailure>.Ok(listResponse);
                },
                err: failure => Result<ListPendingRequestsResponse, FriendFailure>.Err(failure)
            );

            replyTo.Tell(response);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[FRIEND-ACTOR] Error handling ListPendingRequests");
            replyTo.Tell(Result<ListPendingRequestsResponse, FriendFailure>.Err(
                FriendFailure.UnexpectedError("Failed to list pending requests", ex)));
        }
    }
}

