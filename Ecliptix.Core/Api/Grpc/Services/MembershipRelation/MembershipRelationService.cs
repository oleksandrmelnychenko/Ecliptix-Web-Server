using Akka.Actor;
using Ecliptix.Core.Api.Grpc.Base;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;
using Ecliptix.Domain.Memberships.ActorEvents.Contact;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Contact;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Configuration;
using Grpc.Core;
using Microsoft.Extensions.Options;
using DomainContactFailure = Ecliptix.Domain.Memberships.Failures.ContactFailure;

namespace Ecliptix.Core.Api.Grpc.Services.MembershipRelation;

internal sealed class MembershipRelationService : Protobuf.Membership.MembershipRelationService.MembershipRelationServiceBase
{
    private readonly GrpcSecurityService _service;
    private readonly IActorRef _membershipRelationActor;

    public MembershipRelationService(
        IEcliptixActorRegistry actorRegistry,
        IGrpcCipherService grpcCipherService,
        IOptions<SecurityConfiguration> securityConfig)
    {
        _service = new GrpcSecurityService(grpcCipherService, securityConfig);
        _membershipRelationActor = actorRegistry.Get(ActorIds.MembershipRelationActor);
    }

    public override async Task<SecureEnvelope> ListContacts(SecureEnvelope request, ServerCallContext context)
    {
        return await _service.ExecuteEncryptedOperationAsync<ListContactsRequest, ListContactsResponse>(
            request, context,
            async (message, connectId, _, cancellationToken) =>
            {
                byte[] membershipBytes = message.Membership.ToByteArray();
                Guid membershipId = new(membershipBytes);
                int limit = message.Limit > 0 ? message.Limit : 50;

                ListContactsEvent evt = new(
                    connectId,
                    membershipId,
                    limit,
                    message.Cursor,
                    cancellationToken);

                Task<Result<ListContactsResponse, DomainContactFailure>> task =
                    _membershipRelationActor.Ask<Result<ListContactsResponse, DomainContactFailure>>(
                        evt, TimeoutConfiguration.Actor.AskTimeout);

                Result<ListContactsResponse, DomainContactFailure> result =
                    await task.WaitAsync(cancellationToken).ConfigureAwait(false);

                return result.Match(
                    ok: Result<ListContactsResponse, FailureBase>.Ok,
                    err: Result<ListContactsResponse, FailureBase>.Err
                );
            });
    }

    public override async Task<SecureEnvelope> RemoveContact(SecureEnvelope request, ServerCallContext context)
    {
        return await _service.ExecuteEncryptedOperationAsync<RemoveContactRequest, GenericResponse>(
            request, context,
            async (message, connectId, _, cancellationToken) =>
            {
                byte[] byBytes = message.ByMembership.ToByteArray();
                byte[] targetBytes = message.TargetMembership.ToByteArray();
                Guid byMembershipId = new(byBytes);
                Guid targetMembershipId = new(targetBytes);

                RemoveContactEvent evt = new(
                    connectId,
                    byMembershipId,
                    targetMembershipId,
                    cancellationToken);

                Task<Result<GenericResponse, DomainContactFailure>> task =
                    _membershipRelationActor.Ask<Result<GenericResponse, DomainContactFailure>>(
                        evt, TimeoutConfiguration.Actor.AskTimeout);

                Result<GenericResponse, DomainContactFailure> result =
                    await task.WaitAsync(cancellationToken).ConfigureAwait(false);

                return result.Match(
                    ok: Result<GenericResponse, FailureBase>.Ok,
                    err: Result<GenericResponse, FailureBase>.Err
                );
            });
    }

    public override async Task<SecureEnvelope> BlockContact(SecureEnvelope request, ServerCallContext context)
    {
        return await _service.ExecuteEncryptedOperationAsync<BlockContactRequest, GenericResponse>(
            request, context,
            async (message, connectId, _, cancellationToken) =>
            {
                byte[] byBytes = message.ByMembership.ToByteArray();
                byte[] targetBytes = message.TargetMembership.ToByteArray();
                Guid byMembershipId = new(byBytes);
                Guid targetMembershipId = new(targetBytes);

                BlockContactEvent evt = new(
                    connectId,
                    byMembershipId,
                    targetMembershipId,
                    cancellationToken);

                Task<Result<GenericResponse, DomainContactFailure>> task =
                    _membershipRelationActor.Ask<Result<GenericResponse, DomainContactFailure>>(
                        evt, TimeoutConfiguration.Actor.AskTimeout);

                Result<GenericResponse, DomainContactFailure> result =
                    await task.WaitAsync(cancellationToken).ConfigureAwait(false);

                return result.Match(
                    ok: Result<GenericResponse, FailureBase>.Ok,
                    err: Result<GenericResponse, FailureBase>.Err
                );
            });
    }

    public override async Task<SecureEnvelope> UnblockContact(SecureEnvelope request, ServerCallContext context)
    {
        return await _service.ExecuteEncryptedOperationAsync<UnblockContactRequest, GenericResponse>(
            request, context,
            async (message, connectId, _, cancellationToken) =>
            {
                byte[] byBytes = message.ByMembership.ToByteArray();
                byte[] targetBytes = message.TargetMembership.ToByteArray();
                Guid byMembershipId = new(byBytes);
                Guid targetMembershipId = new(targetBytes);

                UnblockContactEvent evt = new(
                    connectId,
                    byMembershipId,
                    targetMembershipId,
                    cancellationToken);

                Task<Result<GenericResponse, DomainContactFailure>> task =
                    _membershipRelationActor.Ask<Result<GenericResponse, DomainContactFailure>>(
                        evt, TimeoutConfiguration.Actor.AskTimeout);

                Result<GenericResponse, DomainContactFailure> result =
                    await task.WaitAsync(cancellationToken).ConfigureAwait(false);

                return result.Match(
                    ok: Result<GenericResponse, FailureBase>.Ok,
                    err: Result<GenericResponse, FailureBase>.Err
                );
            });
    }

    public override async Task<SecureEnvelope> MuteContact(SecureEnvelope request, ServerCallContext context)
    {
        return await _service.ExecuteEncryptedOperationAsync<MuteContactRequest, GenericResponse>(
            request, context,
            async (message, connectId, _, cancellationToken) =>
            {
                byte[] byBytes = message.ByMembership.ToByteArray();
                byte[] targetBytes = message.TargetMembership.ToByteArray();
                Guid byMembershipId = new(byBytes);
                Guid targetMembershipId = new(targetBytes);
                DateTimeOffset mutedUntil = message.MutedUntil.ToDateTimeOffset();

                MuteContactEvent evt = new(
                    connectId,
                    byMembershipId,
                    targetMembershipId,
                    mutedUntil,
                    cancellationToken);

                Task<Result<GenericResponse, DomainContactFailure>> task =
                    _membershipRelationActor.Ask<Result<GenericResponse, DomainContactFailure>>(
                        evt, TimeoutConfiguration.Actor.AskTimeout);

                Result<GenericResponse, DomainContactFailure> result =
                    await task.WaitAsync(cancellationToken).ConfigureAwait(false);

                return result.Match(
                    ok: Result<GenericResponse, FailureBase>.Ok,
                    err: Result<GenericResponse, FailureBase>.Err
                );
            });
    }

    public override async Task<SecureEnvelope> UnmuteContact(SecureEnvelope request, ServerCallContext context)
    {
        return await _service.ExecuteEncryptedOperationAsync<UnmuteContactRequest, GenericResponse>(
            request, context,
            async (message, connectId, _, cancellationToken) =>
            {
                byte[] byBytes = message.ByMembership.ToByteArray();
                byte[] targetBytes = message.TargetMembership.ToByteArray();
                Guid byMembershipId = new(byBytes);
                Guid targetMembershipId = new(targetBytes);

                UnmuteContactEvent evt = new(
                    connectId,
                    byMembershipId,
                    targetMembershipId,
                    cancellationToken);

                Task<Result<GenericResponse, DomainContactFailure>> task =
                    _membershipRelationActor.Ask<Result<GenericResponse, DomainContactFailure>>(
                        evt, TimeoutConfiguration.Actor.AskTimeout);

                Result<GenericResponse, DomainContactFailure> result =
                    await task.WaitAsync(cancellationToken).ConfigureAwait(false);

                return result.Match(
                    ok: Result<GenericResponse, FailureBase>.Ok,
                    err: Result<GenericResponse, FailureBase>.Err
                );
            });
    }

    public override async Task<SecureEnvelope> GetContactStatus(SecureEnvelope request, ServerCallContext context)
    {
        return await _service.ExecuteEncryptedOperationAsync<GetContactStatusRequest, GetContactStatusResponse>(
            request, context,
            async (message, connectId, _, cancellationToken) =>
            {
                byte[] fromBytes = message.FromMembership.ToByteArray();
                byte[] toBytes = message.ToMembership.ToByteArray();
                Guid fromMembershipId = new(fromBytes);
                Guid toMembershipId = new(toBytes);

                GetContactStatusEvent evt = new(
                    connectId,
                    fromMembershipId,
                    toMembershipId,
                    cancellationToken);

                Task<Result<GetContactStatusResponse, DomainContactFailure>> task =
                    _membershipRelationActor.Ask<Result<GetContactStatusResponse, DomainContactFailure>>(
                        evt, TimeoutConfiguration.Actor.AskTimeout);

                Result<GetContactStatusResponse, DomainContactFailure> result =
                    await task.WaitAsync(cancellationToken).ConfigureAwait(false);

                return result.Match(
                    ok: Result<GetContactStatusResponse, FailureBase>.Ok,
                    err: Result<GetContactStatusResponse, FailureBase>.Err
                );
            });
    }
}

