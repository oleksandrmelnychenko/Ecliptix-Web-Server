using Akka.Actor;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.Utilities;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;
using Microsoft.Extensions.Logging;
using Npgsql;
using NpgsqlTypes;
using static System.String;

namespace Ecliptix.Domain.Memberships.Persistors;

public class MembershipPersistorActor : VerificationFlowPersistorBase
{
    public MembershipPersistorActor(
        IDbDataSource npgsqlDataSource,
        ILogger<MembershipPersistorActor> logger)
        : base(npgsqlDataSource, logger)
    {
        Become(Ready);
    }

    public static Props Build(IDbDataSource npgsqlDataSource,
        ILogger<MembershipPersistorActor> logger) =>
        Props.Create(() => new MembershipPersistorActor(npgsqlDataSource, logger));

    private void Ready()
    {
        ReceiveAsync<UpdateMembershipSecureKeyEvent>(HandleUpdateMembershipSecureKeyCommand);
        ReceiveAsync<CreateMembershipActorEvent>(HandleCreateMembershipActorCommand);
        ReceiveAsync<SignInMembershipActorEvent>(HandleSignInMembershipActorCommand);
    }

    public async Task HandleSignInMembershipActorCommand(SignInMembershipActorEvent cmd) =>
        await ExecuteWithConnection(async npgsqlConnection =>
        {
            NpgsqlParameter[] parameters =
            [
                new(Parameters.PhoneNumber, NpgsqlDbType.Varchar) { Value = cmd.PhoneNumber },
                new(Parameters.SecureKey, NpgsqlDbType.Bytea) { Value = cmd.SecureKey }
            ];

            await using IDbCommand command = CreateCommand(npgsqlConnection, Queries.LoginMembership, parameters);
            await using IDbDataReader reader = await command.ExecuteReaderAsync();

            if (!await reader.ReadAsync())
            {
                return Result<Option<MembershipQueryRecord>, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.DataAccess));
            }

            Option<Guid> membershipIdOpt =
                reader.IsDBNull(0) ? Option<Guid>.None : Option<Guid>.Some(reader.GetGuid(0));
            Option<string> activityStatusStrOpt =
                reader.IsDBNull(1) ? Option<string>.None : Option<string>.Some(reader.GetString(1));
            string outcome = reader.GetString(2);

            if (int.TryParse(outcome, out int mins))
            {
                return Result<Option<MembershipQueryRecord>, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.RateLimitExceeded(VerificationFlowMessageKeys.TooManySigninAttempts));
            }

            return (membershipIdOpt, activityStatusStrOpt, outcome) switch
            {
                ({ HasValue: true, Value: var id }, { HasValue: true, Value: var activityStr },
                    VerificationFlowMessageKeys.Success
                    ) =>
                    MapActivityStatus(activityStr) switch
                    {
                        { HasValue: true, Value: var status } =>
                            Result<Option<MembershipQueryRecord>, VerificationFlowFailure>.Ok(
                                Option<MembershipQueryRecord>.Some(new MembershipQueryRecord
                                {
                                    UniqueIdentifier = id,
                                    ActivityStatus = status
                                })),

                        _ => Result<Option<MembershipQueryRecord>, VerificationFlowFailure>.Err(
                            VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.ActivityStatusInvalid))
                    },

                ({ HasValue: false }, _, VerificationFlowMessageKeys.MembershipNotFound) =>
                    Result<Option<MembershipQueryRecord>, VerificationFlowFailure>.Ok(
                        Option<MembershipQueryRecord>.None),

                ({ HasValue: false }, _, VerificationFlowMessageKeys.PhoneNotFound) =>
                    Result<Option<MembershipQueryRecord>, VerificationFlowFailure>.Ok(
                        Option<MembershipQueryRecord>.None),

                var (_, _, error) when IsKnownLoginError(error) =>
                    Result<Option<MembershipQueryRecord>, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.Validation(error)),

                _ => Result<Option<MembershipQueryRecord>, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.PersistorAccess(outcome))
            };
        }, OperationNames.SignInMembership);

    private async Task HandleUpdateMembershipSecureKeyCommand(UpdateMembershipSecureKeyEvent cmd) =>
        await ExecuteWithConnection(async npgsqlConnection =>
        {
            NpgsqlParameter[] parameters =
            [
                new(Parameters.MembershipUniqueId, NpgsqlDbType.Uuid) { Value = cmd.MembershipIdentifier },
                new(Parameters.SecureKey, NpgsqlDbType.Bytea) { Value = cmd.SecureKey }
            ];

            await using IDbCommand command =
                CreateCommand(npgsqlConnection, Queries.UpdateMembershipSecureKey, parameters);
            await using IDbDataReader reader = await command.ExecuteReaderAsync();

            if (!await reader.ReadAsync())
            {
                return Result<Option<MembershipQueryRecord>, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.DataAccess));
            }

            bool success = reader.GetBoolean(0);
            string message = reader.GetString(1);

            if (!success)
            {
                return Result<Option<MembershipQueryRecord>, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Validation(message));
            }

            Option<Guid> membershipIdOpt =
                reader.IsDBNull(2) ? Option<Guid>.None : Option<Guid>.Some(reader.GetGuid(2));
            Option<string> activityStatusStrOpt =
                reader.IsDBNull(3) ? Option<string>.None : Option<string>.Some(reader.GetString(3));
            Option<string> creationStatusStrOpt =
                reader.IsDBNull(4) ? Option<string>.None : Option<string>.Some(reader.GetString(4));

            if (!membershipIdOpt.HasValue || !activityStatusStrOpt.HasValue || !creationStatusStrOpt.HasValue)
            {
                return Result<Option<MembershipQueryRecord>, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.DataAccess));
            }

            Option<Membership.Types.ActivityStatus> activityStatusOpt = MapActivityStatus(activityStatusStrOpt.Value);
            if (!activityStatusOpt.HasValue)
            {
                return Result<Option<MembershipQueryRecord>, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.ActivityStatusInvalid));
            }

            MembershipQueryRecord updateResponse = new()
            {
                UniqueIdentifier = membershipIdOpt.Value,
                ActivityStatus = activityStatusOpt.Value,
                CreationStatus = MembershipCreationStatusHelper.GetCreationStatusEnum(creationStatusStrOpt.Value)
            };


            return Result<Option<MembershipQueryRecord>, VerificationFlowFailure>.Ok(
                Option<MembershipQueryRecord>.Some(updateResponse));
        }, OperationNames.UpdateMembershipSecureKey);

    private async Task HandleCreateMembershipActorCommand(CreateMembershipActorEvent cmd) =>
        await ExecuteWithConnection(async npgsqlConnection =>
        {
            NpgsqlParameter[] parameters =
            [
                new(Parameters.SessionUniqueId, NpgsqlDbType.Uuid) { Value = cmd.SessionIdentifier },
                new(Parameters.ConnectionId, NpgsqlDbType.Bigint) { Value = (long)cmd.ConnectId },
                new(Parameters.OtpUniqueId, NpgsqlDbType.Uuid) { Value = cmd.OtpIdentifier },
                new(Parameters.CreationStatus, NpgsqlDbType.Text)
                    { Value = MembershipCreationStatusHelper.GetCreationStatusString(cmd.CreationStatus) }
            ];

            await using IDbCommand command = CreateCommand(npgsqlConnection, Queries.CreateMembership, parameters);
            await using IDbDataReader reader = await command.ExecuteReaderAsync();

            if (!await reader.ReadAsync())
            {
                return Result<Option<MembershipQueryRecord>, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.DataAccess));
            }

            Option<Guid> membershipIdOpt =
                reader.IsDBNull(0) ? Option<Guid>.None : Option<Guid>.Some(reader.GetGuid(0));
            Option<string> activityStatusStrOpt =
                reader.IsDBNull(1) ? Option<string>.None : Option<string>.Some(reader.GetString(1));
            Option<string> creationStatusStrOpt =
                reader.IsDBNull(2) ? Option<string>.None : Option<string>.Some(reader.GetString(2));
            string outcome = reader.GetString(3);

            if (int.TryParse(outcome, out int _))
            {
                return Result<Option<MembershipQueryRecord>, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.RateLimitExceeded(VerificationFlowMessageKeys.TooManyMembershipAttempts));
            }

            return (membershipIdOpt, activityStatusStrOpt, creationStatusStrOpt, outcome) switch
            {
                ({ HasValue: true, Value: var id },
                    { HasValue: true, Value: var activityStr },
                    { HasValue: true, Value: var creationStr }, var oc
                    and (VerificationFlowMessageKeys.Created or VerificationFlowMessageKeys.MembershipAlreadyExists)) =>
                    MapActivityStatus(activityStr) switch
                    {
                        { HasValue: true, Value: var status } =>
                            Result<Option<MembershipQueryRecord>, VerificationFlowFailure>.Ok(
                                Option<MembershipQueryRecord>.Some(new MembershipQueryRecord
                                {
                                    UniqueIdentifier = id,
                                    ActivityStatus = status,
                                    CreationStatus = MembershipCreationStatusHelper.GetCreationStatusEnum(creationStr)
                                })),

                        _ => Result<Option<MembershipQueryRecord>, VerificationFlowFailure>.Err(
                            VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.ActivityStatusInvalid))
                    },

                var (_, _, _, error) when IsKnownCreationError(error) =>
                    Result<Option<MembershipQueryRecord>, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.Validation(error)),

                _ => Result<Option<MembershipQueryRecord>, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.PersistorAccess(outcome))
            };
        }, OperationNames.CreateMembership);


    private static bool IsKnownLoginError(string outcome) =>
        outcome is VerificationFlowMessageKeys.InvalidSecureKey or
            VerificationFlowMessageKeys.InactiveMembership or
            VerificationFlowMessageKeys.PhoneNumberCannotBeEmpty or
            VerificationFlowMessageKeys.SecureKeyCannotBeEmpty or
            VerificationFlowMessageKeys.SecureKeyNotSet;

    private static bool IsKnownCreationError(string outcome) =>
        outcome is VerificationFlowMessageKeys.CreateMembershipVerificationFlowNotFound;

    private static Option<Membership.Types.ActivityStatus> MapActivityStatus(string? statusStr)
    {
        if (IsNullOrEmpty(statusStr) ||
            !MembershipStatusMap.TryGetValue(statusStr, out Membership.Types.ActivityStatus status))
        {
            return Option<Membership.Types.ActivityStatus>.None;
        }

        return Option<Membership.Types.ActivityStatus>.Some(status);
    }

    private static readonly Dictionary<string, Membership.Types.ActivityStatus> MembershipStatusMap = new()
    {
        ["active"] = Membership.Types.ActivityStatus.Active,
        ["inactive"] = Membership.Types.ActivityStatus.Inactive,
    };
}