using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents.AccountProfile;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Configuration;
using Serilog;

namespace Ecliptix.Domain.Memberships.WorkerActors.AccountProfileActor;

public class AccountProfileActor : ReceiveActor
{

    private readonly IActorRef _profilePersistor;

    private const int MinProfileNameLength = 3;
    private const int MaxProfileNameLength = 30;

    public AccountProfileActor(IActorRef accountProfilePersistor)
    {
        _profilePersistor = accountProfilePersistor;

        ReceiveAsync<CheckProfileNameAvailabilityEvent>(HandleCheckAvailability);
        ReceiveAsync<UpdateAccountProfileEvent>(HandleUpdateProfile);
        ReceiveAsync<GetAccountProfileActorEvent>(HandleGetAccountProfile);
    }

    public static Props Build(IActorRef accountProfilePersistor)
    {
        return Props.Create(() => new AccountProfileActor(accountProfilePersistor));
    }

    private async Task HandleGetAccountProfile(GetAccountProfileActorEvent evt)
    {
        IActorRef replyTo = Sender;
        try
        {
            Result<Option<AccountProfileInfo>, AccountProfileFailure> result =
                await _profilePersistor.Ask<Result<Option<AccountProfileInfo>, AccountProfileFailure>>(
                evt,
                TimeoutConfiguration.Actor.AskTimeout
            );

            replyTo.Tell(result);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[ACCOUNT-PROFILE-ACTOR] Error handling GetAccountProfile");
            replyTo.Tell(Result<Option<AccountProfileInfo>, AccountProfileFailure>.Err(
                AccountProfileFailure.InternalError("Failed to get profile", ex)));
        }
    }

    private async Task HandleCheckAvailability(CheckProfileNameAvailabilityEvent evt)
    {
        IActorRef replyTo = Sender;

        try
        {
            if (string.IsNullOrWhiteSpace(evt.ProfileName) ||
                evt.ProfileName.Length < MinProfileNameLength ||
                evt.ProfileName.Length > MaxProfileNameLength ||
                !IsProfileNameValid(evt.ProfileName))
            {
                replyTo.Tell(Result<bool, AccountProfileFailure>.Ok(false));
                return;
            }

            Task<Result<bool, AccountProfileFailure>> task =
                _profilePersistor.Ask<Result<bool, AccountProfileFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<bool, AccountProfileFailure> result = await task;

            replyTo.Tell(result);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[ACCOUNT-PROFILE-ACTOR] Error handling CheckProfileNameAvailability");
            replyTo.Tell(Result<bool, AccountProfileFailure>.Err(
                AccountProfileFailure.InternalError("Failed to check profile availability", ex)));
        }
    }

    private async Task HandleUpdateProfile(UpdateAccountProfileEvent evt)
    {
        IActorRef replyTo = Sender;

            //TODO temporaly logic, Add real business logic
        try
        {
            if (string.IsNullOrWhiteSpace(evt.ProfileName))
            {
                replyTo.Tell(Result<AccountProfileInfo, AccountProfileFailure>.Err(
                    AccountProfileFailure.ValidationFailed("Profile name cannot be empty.")));
                return;
            }

            if (evt.ProfileName.Length < MinProfileNameLength || evt.ProfileName.Length > MaxProfileNameLength)
            {
                replyTo.Tell(Result<AccountProfileInfo, AccountProfileFailure>.Err(
                    AccountProfileFailure.ValidationFailed($"Profile name must be between {MinProfileNameLength} and {MaxProfileNameLength} characters.")));
                return;
            }

            if (!IsProfileNameValid(evt.ProfileName))
            {
                replyTo.Tell(Result<AccountProfileInfo, AccountProfileFailure>.Err(
                    AccountProfileFailure.ValidationFailed("Profile name contains invalid characters.")));
                return;
            }

            if (string.IsNullOrWhiteSpace(evt.DisplayName))
            {
                replyTo.Tell(Result<AccountProfileInfo, AccountProfileFailure>.Err(
                    AccountProfileFailure.ValidationFailed("Display name cannot be empty.")));
                return;
            }

            Task<Result<AccountProfileInfo, AccountProfileFailure>> task =
                _profilePersistor.Ask<Result<AccountProfileInfo, AccountProfileFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<AccountProfileInfo, AccountProfileFailure> result = await task;

            replyTo.Tell(result);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[ACCOUNT-PROFILE-ACTOR] Error handling UpdateAccountProfile");
            replyTo.Tell(Result<AccountProfileInfo, AccountProfileFailure>.Err(
                AccountProfileFailure.InternalError("Failed to update account profile", ex)));
        }
    }

    private static bool IsProfileNameValid(string profileName)
    {
        return profileName.All(c => char.IsLetterOrDigit(c) || c == '_');
    }
}
