using Akka.Actor;
using Ecliptix.Core.Api.Grpc.Base;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;
using Ecliptix.Domain.Memberships.ActorEvents.Friend;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Friend;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Configuration;
using Grpc.Core;
using Microsoft.Extensions.Options;

namespace Ecliptix.Core.Api.Grpc.Services.Friend;

internal sealed class FriendServices : FriendService.FriendServiceBase
{
    private readonly GrpcSecurityService _service;
    private readonly IActorRef _friendActor;

    public FriendServices(
        IEcliptixActorRegistry actorRegistry,
        IGrpcCipherService grpcCipherService,
        IOptions<SecurityConfiguration> securityConfig)
    {
        _service = new GrpcSecurityService(grpcCipherService, securityConfig);
        _friendActor = actorRegistry.Get(ActorIds.FriendActor);
    }

    public override async Task<SecureEnvelope> SendFriendRequest(SecureEnvelope request, ServerCallContext context)
    {
        return await _service.ExecuteEncryptedOperationAsync<SendFriendRequestRequest, SendFriendRequestResponse>(
            request, context,
            async (message, connectId, _, cancellationToken) =>
            {
                byte[] fromBytes = message.FromMembership.ToByteArray();
                byte[] toBytes = message.ToMembership.ToByteArray();
                Guid fromMembershipId = new Guid(fromBytes);
                Guid toMembershipId = new Guid(toBytes);

                SendFriendRequestEvent evt = new(
                    connectId,
                    fromMembershipId,
                    toMembershipId,
                    message.Message,
                    cancellationToken);

                Task<Result<SendFriendRequestResponse, FriendFailure>> task =
                    _friendActor.Ask<Result<SendFriendRequestResponse, FriendFailure>>(
                        evt, TimeoutConfiguration.Actor.AskTimeout);

                Result<SendFriendRequestResponse, FriendFailure> result =
                    await task.WaitAsync(cancellationToken).ConfigureAwait(false);

                return result.Match(
                    ok: Result<SendFriendRequestResponse, FailureBase>.Ok,
                    err: Result<SendFriendRequestResponse, FailureBase>.Err
                );
            });
    }

    public override async Task<SecureEnvelope> AcceptFriendRequest(SecureEnvelope request, ServerCallContext context)
    {
        return await _service.ExecuteEncryptedOperationAsync<AcceptFriendRequestRequest, GenericResponse>(
            request, context,
            async (message, connectId, _, cancellationToken) =>
            {
                byte[] byBytes = message.ByMembership.ToByteArray();
                byte[] fromBytes = message.FromMembership.ToByteArray();
                Guid byMembershipId = new Guid(byBytes);
                Guid fromMembershipId = new Guid(fromBytes);

                AcceptFriendRequestEvent evt = new(
                    connectId,
                    byMembershipId,
                    fromMembershipId,
                    cancellationToken);

                Task<Result<GenericResponse, FriendFailure>> task =
                    _friendActor.Ask<Result<GenericResponse, FriendFailure>>(
                        evt, TimeoutConfiguration.Actor.AskTimeout);

                Result<GenericResponse, FriendFailure> result =
                    await task.WaitAsync(cancellationToken).ConfigureAwait(false);

                return result.Match(
                    ok: Result<GenericResponse, FailureBase>.Ok,
                    err: Result<GenericResponse, FailureBase>.Err
                );
            });
    }

    public override async Task<SecureEnvelope> ListFriends(SecureEnvelope request, ServerCallContext context)
    {
        return await _service.ExecuteEncryptedOperationAsync<ListFriendsRequest, ListFriendsResponse>(
            request, context,
            async (message, connectId, _, cancellationToken) =>
            {
                byte[] membershipBytes = message.Membership.ToByteArray();
                Guid membershipId = new Guid(membershipBytes);
                int limit = message.Limit > 0 ? message.Limit : 50;

                ListFriendsEvent evt = new(
                    connectId,
                    membershipId,
                    limit,
                    message.Cursor,
                    cancellationToken);

                Task<Result<ListFriendsResponse, FriendFailure>> task =
                    _friendActor.Ask<Result<ListFriendsResponse, FriendFailure>>(
                        evt, TimeoutConfiguration.Actor.AskTimeout);

                Result<ListFriendsResponse, FriendFailure> result =
                    await task.WaitAsync(cancellationToken).ConfigureAwait(false);

                return result.Match(
                    ok: Result<ListFriendsResponse, FailureBase>.Ok,
                    err: Result<ListFriendsResponse, FailureBase>.Err
                );
            });
    }

    public override async Task<SecureEnvelope> CancelFriendRequest(SecureEnvelope request, ServerCallContext context)
    {
        return await _service.ExecuteEncryptedOperationAsync<CancelFriendRequestRequest, GenericResponse>(
            request, context,
            async (message, connectId, _, cancellationToken) =>
            {
                byte[] byBytes = message.ByMembership.ToByteArray();
                byte[] toBytes = message.ToMembership.ToByteArray();
                Guid byMembershipId = new Guid(byBytes);
                Guid toMembershipId = new Guid(toBytes);

                CancelFriendRequestEvent evt = new(
                    connectId,
                    byMembershipId,
                    toMembershipId,
                    cancellationToken);

                Task<Result<GenericResponse, FriendFailure>> task =
                    _friendActor.Ask<Result<GenericResponse, FriendFailure>>(
                        evt, TimeoutConfiguration.Actor.AskTimeout);

                Result<GenericResponse, FriendFailure> result =
                    await task.WaitAsync(cancellationToken).ConfigureAwait(false);

                return result.Match(
                    ok: Result<GenericResponse, FailureBase>.Ok,
                    err: Result<GenericResponse, FailureBase>.Err
                );
            });
    }

    public override async Task<SecureEnvelope> RejectFriendRequest(SecureEnvelope request, ServerCallContext context)
    {
        return await _service.ExecuteEncryptedOperationAsync<RejectFriendRequestRequest, GenericResponse>(
            request, context,
            async (message, connectId, _, cancellationToken) =>
            {
                byte[] byBytes = message.ByMembership.ToByteArray();
                byte[] fromBytes = message.FromMembership.ToByteArray();
                Guid byMembershipId = new Guid(byBytes);
                Guid fromMembershipId = new Guid(fromBytes);

                RejectFriendRequestEvent evt = new(
                    connectId,
                    byMembershipId,
                    fromMembershipId,
                    cancellationToken);

                Task<Result<GenericResponse, FriendFailure>> task =
                    _friendActor.Ask<Result<GenericResponse, FriendFailure>>(
                        evt, TimeoutConfiguration.Actor.AskTimeout);

                Result<GenericResponse, FriendFailure> result =
                    await task.WaitAsync(cancellationToken).ConfigureAwait(false);

                return result.Match(
                    ok: Result<GenericResponse, FailureBase>.Ok,
                    err: Result<GenericResponse, FailureBase>.Err
                );
            });
    }

    public override async Task<SecureEnvelope> RemoveFriend(SecureEnvelope request, ServerCallContext context)
    {
        return await _service.ExecuteEncryptedOperationAsync<RemoveFriendRequest, GenericResponse>(
            request, context,
            async (message, connectId, _, cancellationToken) =>
            {
                byte[] byBytes = message.ByMembership.ToByteArray();
                byte[] friendBytes = message.FriendMembership.ToByteArray();
                Guid byMembershipId = new Guid(byBytes);
                Guid friendMembershipId = new Guid(friendBytes);

                RemoveFriendEvent evt = new(
                    connectId,
                    byMembershipId,
                    friendMembershipId,
                    cancellationToken);

                Task<Result<GenericResponse, FriendFailure>> task =
                    _friendActor.Ask<Result<GenericResponse, FriendFailure>>(
                        evt, TimeoutConfiguration.Actor.AskTimeout);

                Result<GenericResponse, FriendFailure> result =
                    await task.WaitAsync(cancellationToken).ConfigureAwait(false);

                return result.Match(
                    ok: Result<GenericResponse, FailureBase>.Ok,
                    err: Result<GenericResponse, FailureBase>.Err
                );
            });
    }

    public override async Task<SecureEnvelope> BlockUser(SecureEnvelope request, ServerCallContext context)
    {
        return await _service.ExecuteEncryptedOperationAsync<BlockUserRequest, GenericResponse>(
            request, context,
            async (message, connectId, _, cancellationToken) =>
            {
                byte[] byBytes = message.ByMembership.ToByteArray();
                byte[] targetBytes = message.TargetMembership.ToByteArray();
                Guid byMembershipId = new Guid(byBytes);
                Guid targetMembershipId = new Guid(targetBytes);

                BlockUserEvent evt = new(
                    connectId,
                    byMembershipId,
                    targetMembershipId,
                    cancellationToken);

                Task<Result<GenericResponse, FriendFailure>> task =
                    _friendActor.Ask<Result<GenericResponse, FriendFailure>>(
                        evt, TimeoutConfiguration.Actor.AskTimeout);

                Result<GenericResponse, FriendFailure> result =
                    await task.WaitAsync(cancellationToken).ConfigureAwait(false);

                return result.Match(
                    ok: Result<GenericResponse, FailureBase>.Ok,
                    err: Result<GenericResponse, FailureBase>.Err
                );
            });
    }

    public override async Task<SecureEnvelope> UnblockUser(SecureEnvelope request, ServerCallContext context)
    {
        return await _service.ExecuteEncryptedOperationAsync<UnblockUserRequest, GenericResponse>(
            request, context,
            async (message, connectId, _, cancellationToken) =>
            {
                byte[] byBytes = message.ByMembership.ToByteArray();
                byte[] targetBytes = message.TargetMembership.ToByteArray();
                Guid byMembershipId = new Guid(byBytes);
                Guid targetMembershipId = new Guid(targetBytes);

                UnblockUserEvent evt = new(
                    connectId,
                    byMembershipId,
                    targetMembershipId,
                    cancellationToken);

                Task<Result<GenericResponse, FriendFailure>> task =
                    _friendActor.Ask<Result<GenericResponse, FriendFailure>>(
                        evt, TimeoutConfiguration.Actor.AskTimeout);

                Result<GenericResponse, FriendFailure> result =
                    await task.WaitAsync(cancellationToken).ConfigureAwait(false);

                return result.Match(
                    ok: Result<GenericResponse, FailureBase>.Ok,
                    err: Result<GenericResponse, FailureBase>.Err
                );
            });
    }

    public override async Task<SecureEnvelope> ListPendingRequests(SecureEnvelope request, ServerCallContext context)
    {
        return await _service.ExecuteEncryptedOperationAsync<ListPendingRequestsRequest, ListPendingRequestsResponse>(
            request, context,
            async (message, connectId, _, cancellationToken) =>
            {
                byte[] membershipBytes = message.Membership.ToByteArray();
                Guid membershipId = new Guid(membershipBytes);
                int limit = message.Limit > 0 ? message.Limit : 50;
                bool isIncoming = message.Direction == RequestDirection.Incoming;

                ListPendingRequestsEvent evt = new(
                    connectId,
                    membershipId,
                    isIncoming,
                    limit,
                    message.Cursor,
                    cancellationToken);

                Task<Result<ListPendingRequestsResponse, FriendFailure>> task =
                    _friendActor.Ask<Result<ListPendingRequestsResponse, FriendFailure>>(
                        evt, TimeoutConfiguration.Actor.AskTimeout);

                Result<ListPendingRequestsResponse, FriendFailure> result =
                    await task.WaitAsync(cancellationToken).ConfigureAwait(false);

                return result.Match(
                    ok: Result<ListPendingRequestsResponse, FailureBase>.Ok,
                    err: Result<ListPendingRequestsResponse, FailureBase>.Err
                );
            });
    }

    public override async Task<SecureEnvelope> GetFriendshipStatus(SecureEnvelope request, ServerCallContext context)
    {
        return await _service.ExecuteEncryptedOperationAsync<GetFriendshipStatusRequest, GetFriendshipStatusResponse>(
            request, context,
            async (message, connectId, _, cancellationToken) =>
            {
                byte[] fromBytes = message.FromMembership.ToByteArray();
                byte[] toBytes = message.ToMembership.ToByteArray();
                Guid fromMembershipId = new Guid(fromBytes);
                Guid toMembershipId = new Guid(toBytes);

                GetFriendshipStatusEvent evt = new(
                    connectId,
                    fromMembershipId,
                    toMembershipId,
                    cancellationToken);

                Task<Result<GetFriendshipStatusResponse, FriendFailure>> task =
                    _friendActor.Ask<Result<GetFriendshipStatusResponse, FriendFailure>>(
                        evt, TimeoutConfiguration.Actor.AskTimeout);

                Result<GetFriendshipStatusResponse, FriendFailure> result =
                    await task.WaitAsync(cancellationToken).ConfigureAwait(false);

                return result.Match(
                    ok: Result<GetFriendshipStatusResponse, FailureBase>.Ok,
                    err: Result<GetFriendshipStatusResponse, FailureBase>.Err
                );
            });
    }
}

