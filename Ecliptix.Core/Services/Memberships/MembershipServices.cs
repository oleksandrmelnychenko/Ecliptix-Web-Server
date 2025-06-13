using System.Globalization;
using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Domain.Memberships;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.Membership;
using Google.Protobuf;
using Grpc.Core;
using Status = Grpc.Core.Status;

namespace Ecliptix.Core.Services.Memberships;

public class MembershipServices(IActorRegistry actorRegistry, ILogger<MembershipServices> logger)
    : MembershipServicesBase(actorRegistry, logger)
{
    public override async Task<CipherPayload> SignInMembership(CipherPayload request, ServerCallContext context)
    {
        Result<byte[], EcliptixProtocolFailure> decryptionResult = await DecryptRequest(request, context);
        if (decryptionResult.IsErr)
        {
            EcliptixProtocolFailure ecliptixProtocolFailure = decryptionResult.UnwrapErr();
            HandleError(ecliptixProtocolFailure, context);
            return new CipherPayload();
        }

        byte[] decryptedBytes = decryptionResult.Unwrap();
        SignInMembershipRequest signInRequest = Helpers.ParseFromBytes<SignInMembershipRequest>(decryptedBytes);

        ValidatePhoneNumberActorEvent actorEvent = new(signInRequest.PhoneNumber, PeerCulture);
        Result<PhoneNumberValidationResult, VerificationFlowFailure> phoneNumberValidationResult =
            await PhoneNumberValidatorActor.Ask<Result<PhoneNumberValidationResult, VerificationFlowFailure>>(
                actorEvent);

        if (phoneNumberValidationResult.IsErr)
        {
            VerificationFlowFailure verificationFlowFailure = phoneNumberValidationResult.UnwrapErr();
            if (verificationFlowFailure.IsUserFacing)
            {
                byte[]? signInMembershipResponse = new SignInMembershipResponse
                {
                    Result = SignInMembershipResponse.Types.SignInResult.InvalidCredentials,
                    Message = verificationFlowFailure.Message
                }.ToByteArray();

                return await EncryptAndReturnResponse(signInMembershipResponse, context);
            }
            
            HandleVerificationError(verificationFlowFailure, context);
            return new CipherPayload();
        }

        PhoneNumberValidationResult phoneNumberResult = phoneNumberValidationResult.Unwrap();
        if (!phoneNumberResult.IsValid)
        {
            byte[]? signInMembershipResponse = new SignInMembershipResponse
            {
                Result = SignInMembershipResponse.Types.SignInResult.InvalidCredentials,
                Message = phoneNumberResult.MessageKey
            }.ToByteArray();

            return await EncryptAndReturnResponse(signInMembershipResponse, context);
        }

        SignInMembershipActorEvent signInEvent = new(
            phoneNumberResult.ParsedPhoneNumberE164!,
            Helpers.ReadMemoryToRetrieveBytes(signInRequest.SecureKey.Memory), PeerCulture);

        Result<SignInMembershipResponse, VerificationFlowFailure> signInResult =
            await MembershipActor.Ask<Result<SignInMembershipResponse, VerificationFlowFailure>>(
                signInEvent);

        return signInResult.Match(
            signInResponse =>
                EncryptAndReturnResponse(signInResponse.ToByteArray(), context).Result,
            error =>
            {
                HandleVerificationError(error, context);
                return new CipherPayload();
            }
        );
    }

    public override async Task<CipherPayload> UpdateMembershipWithSecureKey(CipherPayload request,
        ServerCallContext context)
    {
        Result<byte[], EcliptixProtocolFailure> decryptResult = await DecryptRequest(request, context);
        if (decryptResult.IsErr)
        {
            HandleError(decryptResult.UnwrapErr(), context);
            return new CipherPayload();
        }

        UpdateMembershipWithSecureKeyRequest updateMembershipWithSecureKeyRequest =
            Helpers.ParseFromBytes<UpdateMembershipWithSecureKeyRequest>(decryptResult.Unwrap());

        UpdateMembershipSecureKeyEvent @event = new(
            Helpers.FromByteStringToGuid(updateMembershipWithSecureKeyRequest.MembershipIdentifier),
            Helpers.ReadMemoryToRetrieveBytes(updateMembershipWithSecureKeyRequest.SecureKey.Memory), PeerCulture);

        Result<UpdateMembershipWithSecureKeyResponse, VerificationFlowFailure> updateOperationResult =
            await MembershipActor.Ask<Result<UpdateMembershipWithSecureKeyResponse, VerificationFlowFailure>>(@event);

        if (updateOperationResult.IsOk)
        {
            return await EncryptAndReturnResponse(updateOperationResult.Unwrap().ToByteArray(), context);
        }

        HandleVerificationError(updateOperationResult.UnwrapErr(), context);
        return new CipherPayload();
    }

    private void HandleVerificationError(VerificationFlowFailure failure, ServerCallContext context)
    {
        if (failure.IsSecurityRelated)
        {
            Logger.LogWarning("Security-related verification error: {Error}", failure.ToStructuredLog());
        }
        else if (!failure.IsUserFacing)
        {
            Logger.LogError("System verification error: {Error}", failure.ToStructuredLog());
        }
        else
        {
            Logger.LogInformation("User verification error: {Error}", failure.ToStructuredLog());
        }

        Status status = failure.ToGrpcStatus();
        throw new RpcException(status);
    }
}