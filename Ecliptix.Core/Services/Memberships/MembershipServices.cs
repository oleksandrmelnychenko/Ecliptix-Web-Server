using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.PhoneNumberValidation;
using Ecliptix.Domain.Memberships.WorkerActors;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.Membership;
using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Core.Services.Memberships;

public class MembershipServices(
    IActorRegistry actorRegistry,
    IPhoneNumberValidator phoneNumberValidator,
    ILogger<MembershipServices> logger)
    : MembershipServicesBase(actorRegistry, logger)
{
    public override async Task<CipherPayload> SignInMembership(CipherPayload request, ServerCallContext context)
    {
        Result<byte[], EcliptixProtocolFailure> decryptionResult = await DecryptRequest(request, context);
        if (decryptionResult.IsErr) throw GrpcFailureException.FromDomainFailure(decryptionResult.UnwrapErr());

        byte[] decryptedBytes = decryptionResult.Unwrap();
        SignInMembershipRequest signInRequest = Helpers.ParseFromBytes<SignInMembershipRequest>(decryptedBytes);

        Result<PhoneNumberValidationResult, VerificationFlowFailure> phoneNumberValidationResult =
            phoneNumberValidator.ValidatePhoneNumber(signInRequest.PhoneNumber, CultureName);

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

            throw GrpcFailureException.FromDomainFailure(verificationFlowFailure);
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
            Helpers.ReadMemoryToRetrieveBytes(signInRequest.SecureKey.Memory), CultureName);

        Result<SignInMembershipResponse, VerificationFlowFailure> signInResult =
            await MembershipActor.Ask<Result<SignInMembershipResponse, VerificationFlowFailure>>(
                signInEvent);

        return signInResult.Match(
            signInResponse =>
                EncryptAndReturnResponse(signInResponse.ToByteArray(), context).Result,
            error => throw GrpcFailureException.FromDomainFailure(error));
    }

    public override async Task<CipherPayload> UpdateMembershipWithSecureKey(CipherPayload request,
        ServerCallContext context)
    {
        Result<byte[], EcliptixProtocolFailure> decryptionResult = await DecryptRequest(request, context);
        if (decryptionResult.IsErr) throw GrpcFailureException.FromDomainFailure(decryptionResult.UnwrapErr());

        UpdateMembershipWithSecureKeyRequest updateMembershipWithSecureKeyRequest =
            Helpers.ParseFromBytes<UpdateMembershipWithSecureKeyRequest>(decryptionResult.Unwrap());

        UpdateMembershipSecureKeyEvent @event = new(
            Helpers.FromByteStringToGuid(updateMembershipWithSecureKeyRequest.MembershipIdentifier),
            Helpers.ReadMemoryToRetrieveBytes(updateMembershipWithSecureKeyRequest.SecureKey.Memory));

        Result<UpdateMembershipWithSecureKeyResponse, VerificationFlowFailure> updateOperationResult =
            await MembershipActor.Ask<Result<UpdateMembershipWithSecureKeyResponse, VerificationFlowFailure>>(@event);

        if (updateOperationResult.IsOk)
            return await EncryptAndReturnResponse(updateOperationResult.Unwrap().ToByteArray(), context);

        throw GrpcFailureException.FromDomainFailure(updateOperationResult.UnwrapErr());
    }
}