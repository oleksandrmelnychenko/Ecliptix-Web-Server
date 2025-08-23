using Akka.Actor;
using Ecliptix.Core.Api.Grpc.Base;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.PhoneNumberValidation;
using Ecliptix.Domain.Memberships.WorkerActors;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Membership;
using OprfRegistrationCompleteResponse = Ecliptix.Protobuf.Membership.OpaqueRegistrationCompleteResponse;
using OprfRecoverySecretKeyCompleteResponse = Ecliptix.Protobuf.Membership.OpaqueRecoverySecretKeyCompleteResponse;
using OprfRecoverySecureKeyInitResponse = Ecliptix.Protobuf.Membership.OpaqueRecoverySecureKeyInitResponse;
using OprfRegistrationInitResponse = Ecliptix.Protobuf.Membership.OpaqueRegistrationInitResponse;
using OprfRegistrationCompleteRequest = Ecliptix.Protobuf.Membership.OpaqueRegistrationCompleteRequest;
using OprfRecoverySecretKeyCompleteRequest = Ecliptix.Protobuf.Membership.OpaqueRecoverySecretKeyCompleteRequest;
using OprfRegistrationInitRequest = Ecliptix.Protobuf.Membership.OpaqueRegistrationInitRequest;
using OprfRecoverySecureKeyInitRequest = Ecliptix.Protobuf.Membership.OpaqueRecoverySecureKeyInitRequest;
using Grpc.Core;
using System.Globalization;

namespace Ecliptix.Core.Api.Grpc.Services.Membership;

public class MembershipServices(
    IEcliptixActorRegistry actorRegistry,
    IPhoneNumberValidator phoneNumberValidator,
    IGrpcCipherService grpcCipherService
) : Protobuf.Membership.MembershipServices.MembershipServicesBase

{
    private readonly EcliptixGrpcServiceBase _baseService = new(grpcCipherService);
    private readonly IActorRef _membershipActor = actorRegistry.Get(ActorIds.MembershipActor);
    private readonly string _cultureName = CultureInfo.CurrentCulture.Name;

    public override async Task<CipherPayload> OpaqueSignInInitRequest(CipherPayload request, ServerCallContext context)
    {
        return await _baseService.ExecuteEncryptedOperationAsync<OpaqueSignInInitRequest, OpaqueSignInInitResponse>(request, context,
            async (message, connectId, ct) =>
            {
                Result<PhoneNumberValidationResult, VerificationFlowFailure> phoneNumberValidationResult =
                    phoneNumberValidator.ValidatePhoneNumber(message.PhoneNumber, _cultureName);

                if (phoneNumberValidationResult.IsErr)
                {
                    VerificationFlowFailure verificationFlowFailure = phoneNumberValidationResult.UnwrapErr();
                    if (verificationFlowFailure.IsUserFacing)
                    {
                        return Result<OpaqueSignInInitResponse, FailureBase>.Ok(new OpaqueSignInInitResponse
                        {
                            Result = OpaqueSignInInitResponse.Types.SignInResult.InvalidCredentials,
                            Message = verificationFlowFailure.Message
                        });
                    }
                    return Result<OpaqueSignInInitResponse, FailureBase>.Err(verificationFlowFailure);
                }

                PhoneNumberValidationResult phoneNumberResult = phoneNumberValidationResult.Unwrap();
                if (!phoneNumberResult.IsValid)
                {
                    return Result<OpaqueSignInInitResponse, FailureBase>.Ok(new OpaqueSignInInitResponse
                    {
                        Result = OpaqueSignInInitResponse.Types.SignInResult.InvalidCredentials,
                        Message = phoneNumberResult.MessageKey
                    });
                }

                SignInMembershipActorEvent signInEvent = new(
                    phoneNumberResult.ParsedPhoneNumberE164!, message, _cultureName);

                Result<OpaqueSignInInitResponse, VerificationFlowFailure> initSignInResult =
                    await _membershipActor.Ask<Result<OpaqueSignInInitResponse, VerificationFlowFailure>>(signInEvent, ct);

                return initSignInResult.Match(
                    ok: Result<OpaqueSignInInitResponse, FailureBase>.Ok,
                    err: Result<OpaqueSignInInitResponse, FailureBase>.Err
                );
            });
    }


    public override async Task<CipherPayload> OpaqueSignInCompleteRequest(CipherPayload request,
        ServerCallContext context)
    {
        return await _baseService.ExecuteEncryptedOperationAsync<OpaqueSignInFinalizeRequest, OpaqueSignInFinalizeResponse>(
                request, context,
                async (message, connectId, ct) =>
                {
                    Result<OpaqueSignInFinalizeResponse, VerificationFlowFailure> finalizeSignInResult =
                        await _membershipActor.Ask<Result<OpaqueSignInFinalizeResponse, VerificationFlowFailure>>(
                            new SignInComplete(message), ct);

                    return finalizeSignInResult.Match(
                        ok: Result<OpaqueSignInFinalizeResponse, FailureBase>.Ok,
                        err: Result<OpaqueSignInFinalizeResponse, FailureBase>.Err
                    );
                });
    }

    public override async Task<CipherPayload> OpaqueRegistrationCompleteRequest(CipherPayload request,
        ServerCallContext context)
    {
        return await _baseService.ExecuteEncryptedOperationAsync<OprfRegistrationCompleteRequest, OprfRegistrationCompleteResponse>(request, context,
                async (message, connectId, ct) =>
                {
                    CompleteRegistrationRecordActorEvent @event = new(
                        Helpers.FromByteStringToGuid(message.MembershipIdentifier),
                        Helpers.ReadMemoryToRetrieveBytes(message.PeerRegistrationRecord.Memory));

                    Result<OprfRegistrationCompleteResponse, VerificationFlowFailure> completeRegistrationRecordResult =
                        await _membershipActor.Ask<Result<OprfRegistrationCompleteResponse, VerificationFlowFailure>>(
                            @event, ct);

                    return completeRegistrationRecordResult.Match(
                        ok: Result<OprfRegistrationCompleteResponse, FailureBase>.Ok,
                        err: Result<OprfRegistrationCompleteResponse, FailureBase>.Err
                    );
                });
    }

    public override async Task<CipherPayload> OpaqueRecoverySecretKeyCompleteRequest(CipherPayload request,
        ServerCallContext context)
    {
        return await _baseService.ExecuteEncryptedOperationAsync<OprfRecoverySecretKeyCompleteRequest, OprfRecoverySecretKeyCompleteResponse>(
            request, context,
            async (message, connectId, ct) =>
            {
                OprfCompleteRecoverySecureKeyEvent @event = new(
                    Helpers.FromByteStringToGuid(message.MembershipIdentifier),
                    Helpers.ReadMemoryToRetrieveBytes(message.PeerRecoveryRecord.Memory));

                Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure> completeRecoverySecretKeyResult =
                    await _membershipActor
                        .Ask<Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure>>(@event, ct);

                return completeRecoverySecretKeyResult.Match(
                    ok: Result<OprfRecoverySecretKeyCompleteResponse, FailureBase>.Ok,
                    err: Result<OprfRecoverySecretKeyCompleteResponse, FailureBase>.Err
                );
            });
    }

    public override async Task<CipherPayload> OpaqueRegistrationInitRequest(CipherPayload request,
        ServerCallContext context)
    {
        return await _baseService.ExecuteEncryptedOperationAsync<OprfRegistrationInitRequest, OprfRegistrationInitResponse>(
                request, context,
                async (message, connectId, ct) =>
                {
                    GenerateMembershipOprfRegistrationRequestEvent @event = new(
                        Helpers.FromByteStringToGuid(message.MembershipIdentifier),
                        Helpers.ReadMemoryToRetrieveBytes(message.PeerOprf.Memory));

                    Result<OprfRegistrationInitResponse, VerificationFlowFailure> updateOperationResult =
                        await _membershipActor.Ask<Result<OprfRegistrationInitResponse, VerificationFlowFailure>>(@event,
                            ct);

                    return updateOperationResult.Match(
                        ok: Result<OprfRegistrationInitResponse, FailureBase>.Ok,
                        err: Result<OprfRegistrationInitResponse, FailureBase>.Err
                    );
                });
    }

    public override async Task<CipherPayload> OpaqueRecoverySecretKeyInitRequest(CipherPayload request, ServerCallContext context)
    {
        return await _baseService.ExecuteEncryptedOperationAsync<OprfRecoverySecureKeyInitRequest, OprfRecoverySecureKeyInitResponse>(request, context,
                async (message, connectId, ct) =>
                {
                    OprfInitRecoverySecureKeyEvent @event = new(
                        Helpers.FromByteStringToGuid(message.MembershipIdentifier),
                        Helpers.ReadMemoryToRetrieveBytes(message.PeerOprf.Memory));

                    Result<OprfRecoverySecureKeyInitResponse, VerificationFlowFailure> result = await _membershipActor
                        .Ask<Result<OprfRecoverySecureKeyInitResponse, VerificationFlowFailure>>(
                            @event, ct);

                    return result.Match(
                        ok: Result<OprfRecoverySecureKeyInitResponse, FailureBase>.Ok,
                        err: Result<OprfRecoverySecureKeyInitResponse, FailureBase>.Err
                    );
                }
            );
    }
}