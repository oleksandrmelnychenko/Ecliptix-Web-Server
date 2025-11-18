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
}

