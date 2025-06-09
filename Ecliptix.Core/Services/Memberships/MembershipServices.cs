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
        Result<byte[], EcliptixProtocolFailure> decryptResult = await DecryptRequest(request, context);

        return await decryptResult.Match<Task<CipherPayload>>(
            ok: async decryptedBytes =>
            {
                SignInMembershipRequest signInRequest = Helpers.ParseFromBytes<SignInMembershipRequest>(decryptedBytes);

                Result<PhoneNumberValidationResult, VerificationFlowFailure> validationResult =
                    await PhoneNumberValidatorActor.Ask<Result<PhoneNumberValidationResult, VerificationFlowFailure>>(
                        new ValidatePhoneNumberActorEvent(signInRequest.PhoneNumber));
                return await validationResult.Match<Task<CipherPayload>>(
                    ok: async phoneNumberValidationResult =>
                    {
                        SignInMembershipActorEvent signInEvent = new(
                            phoneNumberValidationResult.ParsedPhoneNumberE164!,
                            Helpers.ReadMemoryToRetrieveBytes(signInRequest.SecureKey.Memory), PeerCulture);
                        Result<SignInMembershipResponse, VerificationFlowFailure> signInResult =
                            await MembershipActor.Ask<Result<SignInMembershipResponse, VerificationFlowFailure>>(
                                signInEvent);
                        return signInResult.Match(
                            ok: signInResponse =>
                                EncryptAndReturnResponse(signInResponse.ToByteArray(), context).Result,
                            err: error =>
                            {
                                HandleVerificationError(error, context);
                                return new CipherPayload();
                            }
                        );
                    },
                    err: error =>
                    {
                        HandleVerificationError(error, context);
                        return Task.FromResult(new CipherPayload());
                    }
                );
            },
            err: error =>
            {
                HandleError(error, context);
                return Task.FromResult(new CipherPayload());
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