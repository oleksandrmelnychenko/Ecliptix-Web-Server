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
using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Core.Api.Grpc.Services.Membership;

public class MembershipServices(
    IEcliptixActorRegistry actorRegistry,
    IPhoneNumberValidator phoneNumberValidator,
    IGrpcCipherService grpcCipherService
) : MembershipServicesBase(actorRegistry, grpcCipherService)

{
    public override async Task<CipherPayload> OpaqueSignInInitRequest(CipherPayload request, ServerCallContext context)
    {
        return await ExecuteWithDecryption<OpaqueSignInInitRequest, OpaqueSignInInitResponse>(request, context,
            async (message, connectId, ct) =>
            {
                Result<PhoneNumberValidationResult, VerificationFlowFailure> phoneNumberValidationResult =
                    phoneNumberValidator.ValidatePhoneNumber(message.PhoneNumber, CultureName);

                if (phoneNumberValidationResult.IsErr)
                {
                    VerificationFlowFailure verificationFlowFailure = phoneNumberValidationResult.UnwrapErr();
                    if (verificationFlowFailure.IsUserFacing)
                    {
                        byte[] signInMembershipResponse = new OpaqueSignInInitResponse
                        {
                            Result = OpaqueSignInInitResponse.Types.SignInResult.InvalidCredentials,
                            Message = verificationFlowFailure.Message
                        }.ToByteArray();
                        return await GrpcCipherService.CreateSuccessResponse<OpaqueSignInInitResponse>(
                            signInMembershipResponse,
                            connectId, context);
                    }
                }

                PhoneNumberValidationResult phoneNumberResult = phoneNumberValidationResult.Unwrap();
                if (!phoneNumberResult.IsValid)
                {
                    byte[] signInMembershipResponse = new OpaqueSignInInitResponse
                    {
                        Result = OpaqueSignInInitResponse.Types.SignInResult.InvalidCredentials,
                        Message = phoneNumberResult.MessageKey
                    }.ToByteArray();
                    return await GrpcCipherService.CreateSuccessResponse<OpaqueSignInInitResponse>(signInMembershipResponse,
                        connectId, context);
                }

                SignInMembershipActorEvent signInEvent = new(
                    phoneNumberResult.ParsedPhoneNumberE164!, message, CultureName);

                Result<OpaqueSignInInitResponse, VerificationFlowFailure> initSignInResult =
                    await MembershipActor.Ask<Result<OpaqueSignInInitResponse, VerificationFlowFailure>>(signInEvent, 
                        ct);

                return await GrpcCipherService.ProcessResult(initSignInResult, connectId, context);
            });
    }


    public override async Task<CipherPayload> OpaqueSignInCompleteRequest(CipherPayload request,
        ServerCallContext context)
    {
        return await
            ExecuteWithDecryption<OpaqueSignInFinalizeRequest, OpaqueSignInFinalizeResponse>(
                request, context,
                async (message, connectId, ct) =>
                {
                    Result<OpaqueSignInFinalizeResponse, VerificationFlowFailure> finalizeSignInResult =
                        await MembershipActor.Ask<Result<OpaqueSignInFinalizeResponse, VerificationFlowFailure>>(
                            new SignInComplete(message), ct);

                    return await GrpcCipherService.ProcessResult(finalizeSignInResult, connectId, context);
                });
    }

    public override async Task<CipherPayload> OpaqueRegistrationCompleteRequest(CipherPayload request,
        ServerCallContext context)
    {
        return await
            ExecuteWithDecryption<OprfRegistrationCompleteRequest, OprfRegistrationCompleteResponse>(request, context,
                async (message, connectId, ct) =>
                {
                    CompleteRegistrationRecordActorEvent @event = new(
                        Helpers.FromByteStringToGuid(message.MembershipIdentifier),
                        Helpers.ReadMemoryToRetrieveBytes(message.PeerRegistrationRecord.Memory));

                    Result<OprfRegistrationCompleteResponse, VerificationFlowFailure> completeRegistrationRecordResult =
                        await MembershipActor.Ask<Result<OprfRegistrationCompleteResponse, VerificationFlowFailure>>(
                            @event, ct);

                    return await GrpcCipherService.ProcessResult(completeRegistrationRecordResult, connectId,
                        context);
                });
    }

    public override async Task<CipherPayload> OpaqueRecoverySecretKeyCompleteRequest(CipherPayload request,
        ServerCallContext context)
    {
        return await ExecuteWithDecryption<OprfRecoverySecretKeyCompleteRequest, OprfRecoverySecretKeyCompleteResponse>(
            request, context,
            async (message, connectId, ct) =>
            {
                OprfCompleteRecoverySecureKeyEvent @event = new(
                    Helpers.FromByteStringToGuid(message.MembershipIdentifier),
                    Helpers.ReadMemoryToRetrieveBytes(message.PeerRecoveryRecord.Memory));

                Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure> completeRecoverySecretKeyResult =
                    await MembershipActor
                        .Ask<Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure>>(@event, ct);

                return await GrpcCipherService.ProcessResult(completeRecoverySecretKeyResult, connectId, context);
            });
    }

    public override async Task<CipherPayload> OpaqueRegistrationInitRequest(CipherPayload request,
        ServerCallContext context)
    {
        return await
            ExecuteWithDecryption<OprfRegistrationInitRequest, OprfRegistrationInitResponse>(
                request, context,
                async (message, connectId, ct) =>
                {
                    GenerateMembershipOprfRegistrationRequestEvent @event = new(
                        Helpers.FromByteStringToGuid(message.MembershipIdentifier),
                        Helpers.ReadMemoryToRetrieveBytes(message.PeerOprf.Memory));

                    Result<OprfRegistrationInitResponse, VerificationFlowFailure> updateOperationResult =
                        await MembershipActor.Ask<Result<OprfRegistrationInitResponse, VerificationFlowFailure>>(@event,
                            ct);

                    return await GrpcCipherService.ProcessResult(updateOperationResult, connectId, context);
                });
    }

    public override async Task<CipherPayload> OpaqueRecoverySecretKeyInitRequest(CipherPayload request, ServerCallContext context)
    {
        return await
            ExecuteWithDecryption<OprfRecoverySecureKeyInitRequest, OprfRecoverySecureKeyInitResponse>(request, context,
                async (message, connectId, ct) =>
                {
                    OprfInitRecoverySecureKeyEvent @event = new(
                        Helpers.FromByteStringToGuid(message.MembershipIdentifier),
                        Helpers.ReadMemoryToRetrieveBytes(message.PeerOprf.Memory));

                    Result<OprfRecoverySecureKeyInitResponse, VerificationFlowFailure> result = await MembershipActor
                        .Ask<Result<OprfRecoverySecureKeyInitResponse, VerificationFlowFailure>>(
                            @event, ct);

                    return await GrpcCipherService.ProcessResult(result, connectId, context);
                }
            );
    }
}