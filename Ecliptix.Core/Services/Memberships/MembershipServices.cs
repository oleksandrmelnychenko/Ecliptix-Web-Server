using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Protocol.Actors;
using Ecliptix.Core.Services.Utilities;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.OPAQUE;
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
    IPhoneNumberValidator phoneNumberValidator
) : MembershipServicesBase(actorRegistry)
{
    public override async Task<CipherPayload> OpaqueSignInInitRequest(CipherPayload request, ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        DecryptCipherPayloadActorEvent decryptEvent = new(PubKeyExchangeType.DataCenterEphemeralConnect,
            request);

        ForwardToConnectActorEvent decryptForwarder = new(connectId, decryptEvent);

        Result<byte[], EcliptixProtocolFailure> decryptionResult =
            await ProtocolActor.Ask<Result<byte[], EcliptixProtocolFailure>>(decryptForwarder,
                context.CancellationToken);

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
                return await EncryptResponse(signInMembershipResponse, connectId, context);
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
            return await EncryptResponse(signInMembershipResponse, connectId, context);
        }

        SignInMembershipActorEvent signInEvent = new(
            phoneNumberResult.ParsedPhoneNumberE164!, signInRequest, CultureName);

        Result<OpaqueSignInInitResponse, VerificationFlowFailure> signInResult =
            await MembershipActor.Ask<Result<OpaqueSignInInitResponse, VerificationFlowFailure>>(signInEvent,
                context.CancellationToken);

        return await signInResult.Match(
            async signInResponse => await EncryptResponse(signInResponse.ToByteArray(), connectId, context),
            error => throw GrpcFailureException.FromDomainFailure(error));
    }


    public override async Task<CipherPayload> OpaqueSignInCompleteRequest(CipherPayload request,
        ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        DecryptCipherPayloadActorEvent decryptEvent = new(PubKeyExchangeType.DataCenterEphemeralConnect,
            request);

        ForwardToConnectActorEvent decryptForwarder = new(connectId, decryptEvent);

        Result<byte[], EcliptixProtocolFailure> decryptionResult =
            await ProtocolActor.Ask<Result<byte[], EcliptixProtocolFailure>>(decryptForwarder,
                context.CancellationToken);

        if (decryptionResult.IsErr) throw GrpcFailureException.FromDomainFailure(decryptionResult.UnwrapErr());

        byte[] decryptedBytes = decryptionResult.Unwrap();
        OpaqueSignInFinalizeRequest signInRequest = Helpers.ParseFromBytes<OpaqueSignInFinalizeRequest>(decryptedBytes);

        Result<OpaqueSignInFinalizeResponse, VerificationFlowFailure> result =
            await MembershipActor.Ask<Result<OpaqueSignInFinalizeResponse, VerificationFlowFailure>>(
                new SignInComplete(signInRequest));
        
        if (result.IsOk)
            return await EncryptResponse(result.Unwrap().ToByteArray(), connectId, context);

        throw GrpcFailureException.FromDomainFailure(result.UnwrapErr());
    }

    public override async Task<CipherPayload> OpaqueRegistrationCompleteRequest(CipherPayload request,
        ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        DecryptCipherPayloadActorEvent decryptEvent = new(PubKeyExchangeType.DataCenterEphemeralConnect,
            request);

        ForwardToConnectActorEvent decryptForwarder = new(connectId, decryptEvent);

        Result<byte[], EcliptixProtocolFailure> decryptionResult =
            await ProtocolActor.Ask<Result<byte[], EcliptixProtocolFailure>>(decryptForwarder,
                context.CancellationToken);
        if (decryptionResult.IsErr) throw GrpcFailureException.FromDomainFailure(decryptionResult.UnwrapErr());

        OprfRegistrationCompleteRequest opaqueSignInCompleteRequest =
            Helpers.ParseFromBytes<OprfRegistrationCompleteRequest>(decryptionResult.Unwrap());

        CompleteRegistrationRecordActorEvent @event = new(
            Helpers.FromByteStringToGuid(opaqueSignInCompleteRequest.MembershipIdentifier),
            Helpers.ReadMemoryToRetrieveBytes(opaqueSignInCompleteRequest.PeerRegistrationRecord.Memory));

        Result<OprfRegistrationCompleteResponse, VerificationFlowFailure> completeRegistrationRecordResult =
            await MembershipActor.Ask<Result<OprfRegistrationCompleteResponse, VerificationFlowFailure>>(@event);

        if (completeRegistrationRecordResult.IsOk)
            return await EncryptResponse(completeRegistrationRecordResult.Unwrap().ToByteArray(), connectId, context);

        throw GrpcFailureException.FromDomainFailure(completeRegistrationRecordResult.UnwrapErr());
    }

    public override async Task<CipherPayload> OpaqueRecoverySecretKeyCompleteRequest(CipherPayload request,
        ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        DecryptCipherPayloadActorEvent decryptEvent = new(PubKeyExchangeType.DataCenterEphemeralConnect,
            request);
        
        ForwardToConnectActorEvent decryptForwarder = new(connectId, decryptEvent);
        
        Result<byte[], EcliptixProtocolFailure> decryptionResult =
            await ProtocolActor.Ask<Result<byte[], EcliptixProtocolFailure>>(decryptForwarder,
                context.CancellationToken);
        
        if (decryptionResult.IsErr) throw GrpcFailureException.FromDomainFailure(decryptionResult.UnwrapErr());
        
        OprfRecoverySecretKeyCompleteRequest opaqueRecoveryCompleteRequest = 
            Helpers.ParseFromBytes<OprfRecoverySecretKeyCompleteRequest>(decryptionResult.Unwrap());
        
        OprfCompleteRecoverySecureKeyEvent @event = new (
            Helpers.FromByteStringToGuid(opaqueRecoveryCompleteRequest.MembershipIdentifier),
            Helpers.ReadMemoryToRetrieveBytes(opaqueRecoveryCompleteRequest.PeerRecoveryRecord.Memory));
        
        Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure> completeRecoverySecretKeyResult =
            await MembershipActor.Ask<Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure>>(@event);
        
        if(completeRecoverySecretKeyResult.IsOk)
            return await EncryptResponse(completeRecoverySecretKeyResult.Unwrap().ToByteArray(), connectId, context);
        
        throw GrpcFailureException.FromDomainFailure(completeRecoverySecretKeyResult.UnwrapErr());
        
    }

    public override async Task<CipherPayload> OpaqueRegistrationInitRequest(CipherPayload request,
        ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        DecryptCipherPayloadActorEvent decryptEvent = new(PubKeyExchangeType.DataCenterEphemeralConnect,
            request);

        ForwardToConnectActorEvent decryptForwarder = new(connectId, decryptEvent);

        Result<byte[], EcliptixProtocolFailure> decryptionResult =
            await ProtocolActor.Ask<Result<byte[], EcliptixProtocolFailure>>(decryptForwarder,
                context.CancellationToken);

        if (decryptionResult.IsErr) throw GrpcFailureException.FromDomainFailure(decryptionResult.UnwrapErr());

        OprfRegistrationInitRequest opaqueSignInInitRequest =
            Helpers.ParseFromBytes<OprfRegistrationInitRequest>(decryptionResult.Unwrap());

        GenerateMembershipOprfRegistrationRequestEvent @event = new(
            Helpers.FromByteStringToGuid(opaqueSignInInitRequest.MembershipIdentifier),
            Helpers.ReadMemoryToRetrieveBytes(opaqueSignInInitRequest.PeerOprf.Memory));

        Result<OprfRegistrationInitResponse, VerificationFlowFailure> updateOperationResult =
            await MembershipActor.Ask<Result<OprfRegistrationInitResponse, VerificationFlowFailure>>(@event,
                context.CancellationToken);

        if (updateOperationResult.IsOk)
            return await EncryptResponse(updateOperationResult.Unwrap().ToByteArray(), connectId, context);

        throw GrpcFailureException.FromDomainFailure(updateOperationResult.UnwrapErr());
    }

    public override async Task<CipherPayload> OpaqueRecoverySecretKeyInitRequest(CipherPayload request, ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);
        
        Result<byte[], FailureBase> decryptionResult = await DecryptRequest(request, connectId, context);

        if (decryptionResult.IsErr)
        {
            return await RespondFailure<OprfRecoverySecureKeyInitResponse>(decryptionResult.UnwrapErr(), connectId,
                context);
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
            async response => await EncryptResponse(response.ToByteArray(), connectId, context),
            async failureResponse =>
                await RespondFailure<OprfRecoverySecureKeyInitResponse>(failureResponse, connectId, context));
    }

    private async Task<CipherPayload> EncryptResponse(byte[] payload, uint connectId, ServerCallContext context)
    {
        EncryptPayloadActorEvent encryptCommand = new(PubKeyExchangeType.DataCenterEphemeralConnect,
            payload);

        ForwardToConnectActorEvent encryptForwarder = new(connectId, encryptCommand);

        Result<CipherPayload, EcliptixProtocolFailure> encryptResult =
            await ProtocolActor.Ask<Result<CipherPayload, EcliptixProtocolFailure>>(
                encryptForwarder, context.CancellationToken);

        if (encryptResult.IsOk) return encryptResult.Unwrap();

        throw GrpcFailureException.FromDomainFailure(encryptResult.UnwrapErr());
    }

    private async Task<Result<byte[], FailureBase>> DecryptRequest(CipherPayload request, uint connectId,
        ServerCallContext context)
    {
        DecryptCipherPayloadActorEvent decryptEvent = new(PubKeyExchangeType.DataCenterEphemeralConnect, 
            request);
        
        ForwardToConnectActorEvent decryptForwarder = new (connectId, decryptEvent);
        
        Result<byte[], EcliptixProtocolFailure> decryptionResult = 
            await ProtocolActor.Ask<Result<byte[], EcliptixProtocolFailure>>(decryptForwarder,
                context.CancellationToken);

        return decryptionResult.Match(
            ok: success => Result<byte[], FailureBase>.Ok(success),
            err: failure => Result<byte[], FailureBase>.Err(failure)
        );
    }

    private async Task<CipherPayload> RespondFailure<T>(FailureBase failure, uint connectId, ServerCallContext context) where T : IMessage<T>, new()
    {
        context.Status = failure.ToGrpcStatus();
        return await EncryptResponse(new T().ToByteArray(), connectId, context);
    }
}