using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents.Friend;
using Ecliptix.Domain.Memberships.Failures;
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
            Task<Result<FriendEntity, FriendFailure>> task =
                _friendPersistor.Ask<Result<FriendEntity, FriendFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<FriendEntity, FriendFailure> result = await task;

            Result<SendFriendRequestResponse, FriendFailure> response = result.Match(
                ok: relation => Result<SendFriendRequestResponse, FriendFailure>.Ok(
                    new SendFriendRequestResponse
                    {
                        Result = SendFriendRequestResponse.Types.Result.Succeeded
                    }),
                err: failure =>
                {
                    SendFriendRequestResponse.Types.Result resultType = failure.Message switch
                    {
                        var m when m.Contains("already sent") || m.Contains("Already requested") =>
                            SendFriendRequestResponse.Types.Result.AlreadyRequested,
                        var m when m.Contains("Already friends") =>
                            SendFriendRequestResponse.Types.Result.AlreadyFriends,
                        var m when m.Contains("blocked") || m.Contains("Blocked") =>
                            SendFriendRequestResponse.Types.Result.Blocked,
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
            Task<Result<Unit, FriendFailure>> task =
                _friendPersistor.Ask<Result<Unit, FriendFailure>>(evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<Unit, FriendFailure> result = await task;

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
            Task<Result<Unit, FriendFailure>> task =
                _friendPersistor.Ask<Result<Unit, FriendFailure>>(evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<Unit, FriendFailure> result = await task;

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
            Task<Result<Unit, FriendFailure>> task =
                _friendPersistor.Ask<Result<Unit, FriendFailure>>(evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<Unit, FriendFailure> result = await task;

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
            Task<Result<Unit, FriendFailure>> task =
                _friendPersistor.Ask<Result<Unit, FriendFailure>>(evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<Unit, FriendFailure> result = await task;

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
            Task<Result<List<FriendEntity>, FriendFailure>> task =
                _friendPersistor.Ask<Result<List<FriendEntity>, FriendFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<List<FriendEntity>, FriendFailure> result = await task;

            Result<ListFriendsResponse, FriendFailure> response = result.Match(
                ok: friends =>
                {
                    ListFriendsResponse listResponse = new();
                    foreach (FriendEntity f in friends)
                    {
                        Guid otherUserId = f.OtherUserId(evt.MembershipId);
                        listResponse.Friends.Add(new Ecliptix.Protobuf.Friend.Friend
                        {
                            MembershipId = Google.Protobuf.ByteString.CopyFrom(otherUserId.ToByteArray()),
                            Since = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTimeOffset(
                                f.AcceptedAt ?? DateTimeOffset.UtcNow)
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
            Task<Result<FriendEntity?, FriendFailure>> task =
                _friendPersistor.Ask<Result<FriendEntity?, FriendFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<FriendEntity?, FriendFailure> result = await task;

            replyTo.Tell(result);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[FRIEND-ACTOR] Error handling GetFriendshipStatus");
            replyTo.Tell(Result<FriendEntity?, FriendFailure>.Err(
                FriendFailure.UnexpectedError("Failed to get friendship status", ex)));
        }
    }
}

