using Akka.Actor;
using Ecliptix.Core.Protocol;
using Ecliptix.Core.Protocol.Actors;
using Ecliptix.Core.Services.Utilities;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.PhoneNumberValidation;
using Ecliptix.Domain.Memberships.WorkerActors;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Protobuf.PubKeyExchange;
using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Core.Services.Memberships;

public class MembershipServices(
    IEcliptixActorRegistry actorRegistry,
    IPhoneNumberValidator phoneNumberValidator,
    ICipherPayloadHandler cipherPayloadHandler
) : MembershipServicesBase(actorRegistry, cipherPayloadHandler)
{
    public override async Task<CipherPayload> OpaqueSignInInitRequest(CipherPayload request, ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        Result<byte[], FailureBase> decryptionResult =
            await CipherPayloadHandler.DecryptRequest(request, connectId, context);

        if (decryptionResult.IsErr)
        {
            return await CipherPayloadHandler.RespondFailure<OprfRecoverySecureKeyInitResponse>(
                decryptionResult.UnwrapErr(), connectId, context);
        }

        if (decryptionResult.IsErr) throw GrpcFailureException.FromDomainFailure(decryptionResult.UnwrapErr());

        byte[] decryptedBytes = decryptionResult.Unwrap();
        OpaqueSignInInitRequest signInRequest = Helpers.ParseFromBytes<OpaqueSignInInitRequest>(decryptedBytes);

        Result<PhoneNumberValidationResult, VerificationFlowFailure> phoneNumberValidationResult =
            phoneNumberValidator.ValidatePhoneNumber(signInRequest.PhoneNumber, CultureName);

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
                return await CipherPayloadHandler.RespondSuccess<OpaqueSignInInitResponse>(signInMembershipResponse,
                    connectId, context);
            }

            throw GrpcFailureException.FromDomainFailure(verificationFlowFailure);
        }

        PhoneNumberValidationResult phoneNumberResult = phoneNumberValidationResult.Unwrap();
        if (!phoneNumberResult.IsValid)
        {
            byte[] signInMembershipResponse = new OpaqueSignInInitResponse
            {
                Result = OpaqueSignInInitResponse.Types.SignInResult.InvalidCredentials,
                Message = phoneNumberResult.MessageKey
            }.ToByteArray();
            return await CipherPayloadHandler.RespondSuccess<OpaqueSignInInitResponse>(signInMembershipResponse,
                connectId, context);
        }

        SignInMembershipActorEvent signInEvent = new(
            phoneNumberResult.ParsedPhoneNumberE164!, signInRequest, CultureName);

        Result<OpaqueSignInInitResponse, VerificationFlowFailure> initSignInResult =
            await MembershipActor.Ask<Result<OpaqueSignInInitResponse, VerificationFlowFailure>>(signInEvent,
                context.CancellationToken);

        return await initSignInResult.Match(
            async response =>
                await CipherPayloadHandler.RespondSuccess<OpaqueSignInInitResponse>(response.ToByteArray(),
                    connectId, context),
            async error =>
                await CipherPayloadHandler.RespondFailure<OpaqueSignInInitResponse>(error, connectId, context)
        );
    }


    public override async Task<CipherPayload> OpaqueSignInCompleteRequest(CipherPayload request,
        ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        DecryptCipherPayloadActorEvent decryptEvent = new(PubKeyExchangeType.DataCenterEphemeralConnect,
            request);

        ForwardToConnectActorEvent decryptForwarder = new(connectId, decryptEvent);

        Result<byte[], FailureBase> decryptionResult =
            await CipherPayloadHandler.DecryptRequest(request, connectId, context);

        if (decryptionResult.IsErr)
        {
            return await CipherPayloadHandler.RespondFailure<OprfRecoverySecureKeyInitResponse>(
                decryptionResult.UnwrapErr(), connectId, context);
        }

        if (decryptionResult.IsErr) throw GrpcFailureException.FromDomainFailure(decryptionResult.UnwrapErr());

        byte[] decryptedBytes = decryptionResult.Unwrap();
        OpaqueSignInFinalizeRequest signInRequest = Helpers.ParseFromBytes<OpaqueSignInFinalizeRequest>(decryptedBytes);

        Result<OpaqueSignInFinalizeResponse, VerificationFlowFailure> finalizeSignInResult =
            await MembershipActor.Ask<Result<OpaqueSignInFinalizeResponse, VerificationFlowFailure>>(
                new SignInComplete(signInRequest));
        
        return await finalizeSignInResult.Match(
            async response =>
                await CipherPayloadHandler.RespondSuccess<OpaqueSignInFinalizeResponse>(response.ToByteArray(),
                    connectId, context),
            async error =>
                await CipherPayloadHandler.RespondFailure<OpaqueSignInFinalizeResponse>(error, connectId, context)
        );
    }

    public override async Task<CipherPayload> OpaqueRegistrationCompleteRequest(CipherPayload request,
        ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        Result<byte[], FailureBase> decryptionResult =
            await CipherPayloadHandler.DecryptRequest(request, connectId, context);

        if (decryptionResult.IsErr)
        {
            return await CipherPayloadHandler.RespondFailure<OprfRecoverySecureKeyInitResponse>(
                decryptionResult.UnwrapErr(), connectId, context);
        }

        OprfRegistrationCompleteRequest opaqueSignInCompleteRequest =
            Helpers.ParseFromBytes<OprfRegistrationCompleteRequest>(decryptionResult.Unwrap());

        CompleteRegistrationRecordActorEvent @event = new(
            Helpers.FromByteStringToGuid(opaqueSignInCompleteRequest.MembershipIdentifier),
            Helpers.ReadMemoryToRetrieveBytes(opaqueSignInCompleteRequest.PeerRegistrationRecord.Memory));

        Result<OprfRegistrationCompleteResponse, VerificationFlowFailure> completeRegistrationRecordResult =
            await MembershipActor.Ask<Result<OprfRegistrationCompleteResponse, VerificationFlowFailure>>(@event);

        return await completeRegistrationRecordResult.Match(
            async response =>
                await CipherPayloadHandler.RespondSuccess<OprfRegistrationCompleteResponse>(response.ToByteArray(),
                    connectId, context),
            async error =>
                await CipherPayloadHandler.RespondFailure<OprfRegistrationCompleteResponse>(error, connectId, context)
        );
    }

    public override async Task<CipherPayload> OpaqueRecoverySecretKeyCompleteRequest(CipherPayload request,
        ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        Result<byte[], FailureBase> decryptionResult =
            await CipherPayloadHandler.DecryptRequest(request, connectId, context);

        if (decryptionResult.IsErr)
        {
            return await CipherPayloadHandler.RespondFailure<OprfRecoverySecureKeyInitResponse>(
                decryptionResult.UnwrapErr(), connectId, context);
        }
        
        OprfRecoverySecretKeyCompleteRequest opaqueRecoveryCompleteRequest = 
            Helpers.ParseFromBytes<OprfRecoverySecretKeyCompleteRequest>(decryptionResult.Unwrap());
        
        OprfCompleteRecoverySecureKeyEvent @event = new (
            Helpers.FromByteStringToGuid(opaqueRecoveryCompleteRequest.MembershipIdentifier),
            Helpers.ReadMemoryToRetrieveBytes(opaqueRecoveryCompleteRequest.PeerRecoveryRecord.Memory));
        
        Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure> completeRecoverySecretKeyResult =
            await MembershipActor.Ask<Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure>>(@event);
        
        return await completeRecoverySecretKeyResult.Match(
            async response =>
                await CipherPayloadHandler.RespondSuccess<OprfRecoverySecretKeyCompleteResponse>(response.ToByteArray(),
                    connectId, context),
            async error =>
                await CipherPayloadHandler.RespondFailure<OprfRecoverySecretKeyCompleteResponse>(error, connectId, context)
        );
    }

    public override async Task<CipherPayload> OpaqueRegistrationInitRequest(CipherPayload request,
        ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        Result<byte[], FailureBase> decryptionResult =
            await CipherPayloadHandler.DecryptRequest(request, connectId, context);

        if (decryptionResult.IsErr)
        {
            return await CipherPayloadHandler.RespondFailure<OprfRecoverySecureKeyInitResponse>(
                decryptionResult.UnwrapErr(), connectId, context);
        }

        OprfRegistrationInitRequest opaqueSignInInitRequest =
            Helpers.ParseFromBytes<OprfRegistrationInitRequest>(decryptionResult.Unwrap());

        GenerateMembershipOprfRegistrationRequestEvent @event = new(
            Helpers.FromByteStringToGuid(opaqueSignInInitRequest.MembershipIdentifier),
            Helpers.ReadMemoryToRetrieveBytes(opaqueSignInInitRequest.PeerOprf.Memory));

        Result<OprfRegistrationInitResponse, VerificationFlowFailure> updateOperationResult =
            await MembershipActor.Ask<Result<OprfRegistrationInitResponse, VerificationFlowFailure>>(@event,
                context.CancellationToken);

        return await updateOperationResult.Match(
            async response =>
                await CipherPayloadHandler.RespondSuccess<OprfRegistrationInitResponse>(response.ToByteArray(),
                    connectId, context),
            async error =>
                await CipherPayloadHandler.RespondFailure<OprfRegistrationInitResponse>(error, connectId, context)
        );
    }

    public override async Task<CipherPayload> OpaqueRecoverySecretKeyInitRequest(CipherPayload request, ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        Result<byte[], FailureBase> decryptionResult =
            await CipherPayloadHandler.DecryptRequest(request, connectId, context);

        if (decryptionResult.IsErr)
        {
            return await CipherPayloadHandler.RespondFailure<OprfRecoverySecureKeyInitResponse>(
                decryptionResult.UnwrapErr(), connectId, context);
        }
        
        OprfRecoverySecureKeyInitRequest opaqueRecoveryInitRequest =
            Helpers.ParseFromBytes<OprfRecoverySecureKeyInitRequest>(decryptionResult.Unwrap());

        OprfInitRecoverySecureKeyEvent @event = new(
            Helpers.FromByteStringToGuid(opaqueRecoveryInitRequest.MembershipIdentifier),
            Helpers.ReadMemoryToRetrieveBytes(opaqueRecoveryInitRequest.PeerOprf.Memory));
        
        Result<OprfRecoverySecureKeyInitResponse, VerificationFlowFailure> updateOperationResult = 
            await MembershipActor.Ask<Result<OprfRecoverySecureKeyInitResponse, VerificationFlowFailure>>(@event, 
                context.CancellationToken);

        return await updateOperationResult.Match(
            async response =>
                await CipherPayloadHandler.RespondSuccess<OprfRecoverySecureKeyInitResponse>(response.ToByteArray(),
                    connectId, context),
            async error =>
                await CipherPayloadHandler.RespondFailure<OprfRecoverySecureKeyInitResponse>(error, connectId, context)
        );
    }
}