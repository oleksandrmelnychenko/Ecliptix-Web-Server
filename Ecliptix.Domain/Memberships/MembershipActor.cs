using Akka.Actor;
using Ecliptix.Domain.Persistors;
using Ecliptix.Domain.Persistors.QueryRecords;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;
using Microsoft.Extensions.Localization;

namespace Ecliptix.Domain.Memberships;

public record SignInMembershipActorCommand(string PhoneNumber, byte[] SecureKey);
public record UpdateMembershipSecureKeyCommand(Guid MembershipIdentifier, byte[] SecureKey);

public class MembershipActor : ReceiveActor
{
    private readonly IActorRef _persistor;
    private readonly IStringLocalizer<MembershipActor> _localizer;

    private const string InvalidCredentials = "invalid_credentials";

    private const string MinutesUntilLoginRetry = "minutes_until_login_retry";
    
    public MembershipActor(IActorRef persistor, IStringLocalizer<MembershipActor> localizer)
    {
        _persistor = persistor;
        _localizer = localizer;

        Become(Ready);
    }

    public static Props Build(IActorRef persistor, IStringLocalizer<MembershipActor> localizer) =>
        Props.Create(() => new MembershipActor(persistor, localizer));

    private void Ready()
    {
        ReceiveAsync<UpdateMembershipSecureKeyCommand>(HandleUpdateMembershipSecureKeyCommand);
        ReceiveAsync<CreateMembershipActorCommand>(HandleCreateMembershipActorCommand);
        ReceiveAsync<SignInMembershipActorCommand>(HandleSignInMembershipActorCommand);
    }

    private Task HandleUpdateMembershipSecureKeyCommand(UpdateMembershipSecureKeyCommand arg)
    {
        throw new NotImplementedException();
    }

    private async Task HandleCreateMembershipActorCommand(CreateMembershipActorCommand command)
    {
        Result<Option<MembershipQueryRecord>, ShieldFailure> operationResult =
            await _persistor.Ask<Result<Option<MembershipQueryRecord>, ShieldFailure>>(command);
        Sender.Tell(operationResult);
    }

    private async Task HandleSignInMembershipActorCommand(SignInMembershipActorCommand command)
    {
        Result<Option<MembershipQueryRecord>, ShieldFailure> result =
            await _persistor.Ask<Result<Option<MembershipQueryRecord>, ShieldFailure>>(command);

        Result<SignInMembershipResponse, ShieldFailure> operationResult = result.Match(
            ok: option => option.Match(
                record => Result<SignInMembershipResponse, ShieldFailure>.Ok(
                    new SignInMembershipResponse
                    {
                        Membership = new Membership
                        {
                            UniqueIdentifier = Helpers.GuidToByteString(record.UniqueIdentifier),
                            Status = record.Status
                        },
                        Result = SignInMembershipResponse.Types.SignInResult.Succeeded
                    }
                ),
                () => Result<SignInMembershipResponse, ShieldFailure>.Ok(
                    new SignInMembershipResponse
                    {
                        Result = SignInMembershipResponse.Types.SignInResult.InvalidCredentials,
                        Message = _localizer[InvalidCredentials].Value
                    }
                )
            ),
            err =>
            {
                if (err.Type == ShieldFailureType.InvalidInput)
                {
                    return Result<SignInMembershipResponse, ShieldFailure>.Ok(
                        new SignInMembershipResponse
                        {
                            Result = SignInMembershipResponse.Types.SignInResult.LoginAttemptExceeded,
                            Message = _localizer[MinutesUntilLoginRetry].Value,
                            MinutesUntilRetry = err.Message
                        }
                    );
                }

                return Result<SignInMembershipResponse, ShieldFailure>.Err(err);
            }
        );

        Sender.Tell(operationResult);
    }
}