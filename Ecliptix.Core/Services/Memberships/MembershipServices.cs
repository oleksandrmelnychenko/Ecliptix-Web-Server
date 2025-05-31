using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Services.Utilities;
using Ecliptix.Domain.Memberships;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Protobuf.PubKeyExchange;
using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Core.Services.Memberships;

public class MembershipServices(IActorRegistry actorRegistry, ILogger<MembershipServices> logger)
    : MembershipServicesBase(actorRegistry, logger)
{
    public override async Task<CipherPayload> SignInMembership(CipherPayload request, ServerCallContext context)
    {
        Result<byte[], ShieldFailure> decryptResult = await DecryptRequest(request, context);
        if (decryptResult.IsErr)
        {
            HandleError(decryptResult.UnwrapErr(), context);
            return new CipherPayload();
        }

        SignInMembershipRequest signInRequest =
            Helpers.ParseFromBytes<SignInMembershipRequest>(decryptResult.Unwrap());

        ValidatePhoneNumberCommand actorCommand = new(signInRequest.PhoneNumber);

        Result<PhoneNumberValidationResult, ShieldFailure> validationResult = await PhoneNumberValidatorActor
            .Ask<Result<PhoneNumberValidationResult, ShieldFailure>>(actorCommand);

        if (validationResult.IsOk)
        {
            PhoneNumberValidationResult phoneNumberValidationResult = validationResult.Unwrap();

            SignInMembershipActorCommand command = new(phoneNumberValidationResult.ParsedPhoneNumberE164!,
                Helpers.ReadMemoryToRetrieveBytes(signInRequest.SecureKey.Memory));

            Result<SignInMembershipResponse, ShieldFailure> signInResult =
                await MembershipActor.Ask<Result<SignInMembershipResponse, ShieldFailure>>(command);

            if (signInResult.IsOk)
            {
                return await EncryptAndReturnResponse(signInResult.Unwrap().ToByteArray(), context);
            }
        }

        HandleError(validationResult.UnwrapErr(), context);
        return new CipherPayload();
    }

    public override Task<CipherPayload> UpdateMembershipWithSecureKey(CipherPayload request, ServerCallContext context)
    {
        return base.UpdateMembershipWithSecureKey(request, context);
    }

}