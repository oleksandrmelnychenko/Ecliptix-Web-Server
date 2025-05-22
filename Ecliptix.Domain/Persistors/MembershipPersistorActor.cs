using Akka.Actor;
using Ecliptix.Domain.Memberships;
using Ecliptix.Domain.Persistors.QueryRecords;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;
using Npgsql;
using NpgsqlTypes;

namespace Ecliptix.Domain.Persistors;

public sealed class MembershipPersistorActor : PersistorBase
{
    private const string LoginMembershipSql =
        "SELECT membership_unique_id, status, outcome FROM login_membership(@phone_number, @secure_key)";

    private const string CreateMembershipSql =
        "SELECT membership_unique_id, status, outcome FROM create_membership(@session_unique_id, @connection_id, @secure_key)";

    private const string LoginNoResultsError = "Stored procedure login_membership returned no results.";
    private const string CreateNoResultsError = "Stored procedure create_membership returned no results.";

    private const string SuccessOutcome = "success";
    private const string MembershipNotFoundOutcome = "membership_not_found";
    private const string PhoneNumberNotFoundOutcome = "phone_number_not_found";
    private const string InvalidSecureKeyOutcome = "invalid_secure_key";
    private const string InactiveMembershipOutcome = "inactive_membership";
    private const string PhoneNumberCannotBeEmptyOutcome = "phone_number_cannot_be_empty";
    private const string SecureKeyCannotBeEmptyOutcome = "secure_key_cannot_be_empty";
    private const string SecureKeyTooLongOutcome = "secure_key_too_long";
    private const string VerificationSessionNotFoundOutcome = "verification_session_not_found";
    private const string VerificationSessionNotVerifiedOutcome = "verification_session_not_verified";
    private const string OtpNotVerifiedOutcome = "otp_not_verified";
    private const string CreatedOutcome = "created";
    private const string MembershipAlreadyExistsOutcome = "membership_already_exists";

    private const string NullStatusErrorFormat =
        "Membership status string was null for a successful-like outcome '{0}'. This indicates an unexpected DB state.";

    private const string UnknownStatusErrorFormat =
        "Unknown membership status string: '{0}' received from database for outcome '{1}'.";

    private static readonly Dictionary<string, Membership.Types.MembershipStatus> MembershipStatusMap = new()
    {
        ["active"] = Membership.Types.MembershipStatus.Active,
        ["inactive"] = Membership.Types.MembershipStatus.Inactive,
    };

    public MembershipPersistorActor(NpgsqlDataSource npgsqlDataSource) : base(npgsqlDataSource)
    {
        Become(Ready);
    }

    public static Props Build(NpgsqlDataSource npgsqlDataSource) =>
        Props.Create(() => new MembershipPersistorActor(npgsqlDataSource));

    private void Ready()
    {
        ReceiveAsync<CreateMembershipActorCommand>(HandleCreateMembershipActorCommand);
        ReceiveAsync<SignInMembershipActorCommand>(HandleSignInMembershipActorCommand);
    }

    private async Task HandleSignInMembershipActorCommand(SignInMembershipActorCommand cmd) =>
        await ExecuteWithConnection(async npgsqlConnection =>
        {
            NpgsqlParameter[] parameters =
            [
                new("phone_number", NpgsqlDbType.Varchar) { Value = cmd.PhoneNumber },
                new("secure_key", NpgsqlDbType.Bytea) { Value = cmd.SecureKey }
            ];

            await using NpgsqlCommand command = CreateCommand(npgsqlConnection, LoginMembershipSql, parameters);
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();

            if (!await reader.ReadAsync())
            {
                return Result<Option<MembershipQueryRecord>, ShieldFailure>.Err(
                    ShieldFailure.DataAccess(LoginNoResultsError));
            }

            Option<Guid> membershipIdOpt =
                reader.IsDBNull(0) ? Option<Guid>.None : Option<Guid>.Some(reader.GetGuid(0));
            Option<string> statusStrOpt =
                reader.IsDBNull(1) ? Option<string>.None : Option<string>.Some(reader.GetString(1));
            string outcome = reader.GetString(2);

            if (int.TryParse(outcome, out int waitMinutes))
            {
                return Result<Option<MembershipQueryRecord>, ShieldFailure>.Err(
                    ShieldFailure.InvalidInput($"{waitMinutes}"));
            }

            return (membershipIdOpt, statusStrOpt, outcome) switch
            {
                ({ HasValue: true, Value: var id },
                    { HasValue: true, Value: var statusStr }, SuccessOutcome) =>
                    Result<Option<MembershipQueryRecord>, ShieldFailure>.Ok(
                        Option<MembershipQueryRecord>.Some(new MembershipQueryRecord
                        {
                            UniqueIdentifier = id,
                            Status = MapStatus(statusStr, outcome)
                        })),

                ({ HasValue: false }, _, MembershipNotFoundOutcome) =>
                    Result<Option<MembershipQueryRecord>, ShieldFailure>.Ok(Option<MembershipQueryRecord>.None),

                ({ HasValue: false }, _, PhoneNumberNotFoundOutcome) =>
                    Result<Option<MembershipQueryRecord>, ShieldFailure>.Ok(Option<MembershipQueryRecord>.None),

                var (_, _, error) when IsKnownLoginError(error) =>
                    Result<Option<MembershipQueryRecord>, ShieldFailure>.Err(
                        ShieldFailure.InvalidInput(error)),

                _ => Result<Option<MembershipQueryRecord>, ShieldFailure>.Err(
                    ShieldFailure.DataAccess(outcome))
            };
        }, "login membership");

    private async Task HandleCreateMembershipActorCommand(CreateMembershipActorCommand cmd) =>
        await ExecuteWithConnection(async npgsqlConnection =>
        {
            NpgsqlParameter[] parameters =
            [
                new("session_unique_id", NpgsqlDbType.Uuid) { Value = cmd.SessionIdentifier },
                new("connection_id", NpgsqlDbType.Bigint) { Value = cmd.ConnectId },
                new("secure_key", NpgsqlDbType.Bytea) { Value = cmd.SecureKey }
            ];

            await using NpgsqlCommand command = CreateCommand(npgsqlConnection, CreateMembershipSql, parameters);
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();

            if (!await reader.ReadAsync())
            {
                return Result<Option<MembershipQueryRecord>, ShieldFailure>.Err(
                    ShieldFailure.DataAccess(CreateNoResultsError));
            }

            Option<Guid> membershipIdOpt =
                reader.IsDBNull(0) ? Option<Guid>.None : Option<Guid>.Some(reader.GetGuid(0));
            Option<string> statusStrOpt =
                reader.IsDBNull(1) ? Option<string>.None : Option<string>.Some(reader.GetString(1));
            string outcome = reader.GetString(2);

            return (membershipIdOpt, statusStrOpt, outcome) switch
            {
                ({ HasValue: true, Value: var id }, { HasValue: true, Value: var statusStr }, var oc
                    and (CreatedOutcome or MembershipAlreadyExistsOutcome)) =>
                    Result<Option<MembershipQueryRecord>, ShieldFailure>.Ok(
                        Option<MembershipQueryRecord>.Some(new MembershipQueryRecord
                        {
                            UniqueIdentifier = id,
                            Status = MapStatus(statusStr, oc)
                        })),

                var (_, _, error) when IsKnownCreationError(error) =>
                    Result<Option<MembershipQueryRecord>, ShieldFailure>.Err(
                        ShieldFailure.InvalidInput(error)),

                _ => Result<Option<MembershipQueryRecord>, ShieldFailure>.Err(
                    ShieldFailure.DataAccess(outcome))
            };
        }, "create membership");

    private static bool IsKnownLoginError(string outcome) =>
        outcome is InvalidSecureKeyOutcome
            or InactiveMembershipOutcome
            or PhoneNumberCannotBeEmptyOutcome
            or SecureKeyCannotBeEmptyOutcome
            or SecureKeyTooLongOutcome
        && !int.TryParse(outcome, out _);

    private static bool IsKnownCreationError(string outcome) => outcome is
        SecureKeyCannotBeEmptyOutcome
        or SecureKeyTooLongOutcome
        or VerificationSessionNotFoundOutcome
        or VerificationSessionNotVerifiedOutcome
        or OtpNotVerifiedOutcome;

    private static Membership.Types.MembershipStatus MapStatus(string? statusStr, string outcomeForContext)
    {
        if (statusStr == null)
        {
            throw new InvalidOperationException(string.Format(NullStatusErrorFormat, outcomeForContext));
        }

        if (!MembershipStatusMap.TryGetValue(statusStr, out Membership.Types.MembershipStatus status))
        {
            throw new InvalidOperationException(string.Format(UnknownStatusErrorFormat, statusStr, outcomeForContext));
        }

        return status;
    }
}