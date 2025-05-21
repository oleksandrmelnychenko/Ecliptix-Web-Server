using Akka.Actor;
using Ecliptix.Domain.Memberships;
using Ecliptix.Domain.Persistors.QueryRecords;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;
using Npgsql;
using NpgsqlTypes;

namespace Ecliptix.Domain.Persistors;

public class MembershipPersistorActor : PersistorBase
{
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

    private async Task HandleSignInMembershipActorCommand(SignInMembershipActorCommand cmd)
    {
        await ExecuteWithConnection(
            async conn =>
            {
                NpgsqlParameter[] parameters =
                [
                    new("phone_number", NpgsqlDbType.Varchar) { Value = cmd.PhoneNumber },
                    new("secure_key", NpgsqlDbType.Varchar) { Value = cmd.SecureKey }
                ];

                const string sql = @"
                    SELECT membership_unique_id, status, outcome
                    FROM login_membership(@phone_number, @secure_key)";

                await using NpgsqlCommand command = CreateCommand(conn, sql, parameters);
                await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();

                if (!await reader.ReadAsync())
                {
                    return Result<MembershipQueryRecord, ShieldFailure>.Err(
                        ShieldFailure.DataAccess("Stored procedure login_membership returned no results."));
                }

                int membershipIdOrdinal = reader.GetOrdinal("membership_unique_id");
                int statusOrdinal = reader.GetOrdinal("status");
                int outcomeOrdinal = reader.GetOrdinal("outcome");

                Guid? membershipId = reader.IsDBNull(membershipIdOrdinal) ? null : reader.GetGuid(membershipIdOrdinal);
                string? statusStr = reader.IsDBNull(statusOrdinal) ? null : reader.GetString(statusOrdinal);
                string outcome = reader.GetString(outcomeOrdinal);

                Membership.Types.MembershipStatus status = statusStr switch
                {
                    "active" => Membership.Types.MembershipStatus.Active,
                    "inactive" => Membership.Types.MembershipStatus.Inactive,
                    _ => throw new InvalidOperationException($"Unknown membership status: {statusStr}")
                };

                return (membershipId, outcome) switch
                {
                    (Guid id, "success") => Result<MembershipQueryRecord, ShieldFailure>.Ok(
                        new MembershipQueryRecord
                        {
                            UniqueIdentifier = id,
                            Status = status
                        }),
                    (null, var err) => Result<MembershipQueryRecord, ShieldFailure>.Err(
                        ShieldFailure.InvalidInput($"Login failed: {err}")),
                    _ => Result<MembershipQueryRecord, ShieldFailure>.Err(
                        ShieldFailure.DataAccess($"Unexpected outcome: {outcome}"))
                };
            },
            "login membership");
    }

    private async Task HandleCreateMembershipActorCommand(CreateMembershipActorCommand cmd)
    {
        await ExecuteWithConnection(
            async conn =>
            {
                NpgsqlParameter[] parameters =
                [
                    new("session_unique_id", NpgsqlDbType.Uuid) { Value = cmd.SessionIdentifier },
                    new("connection_id", NpgsqlDbType.Bigint) { Value = cmd.ConnectId },
                    new("secure_key", NpgsqlDbType.Varchar) { Value = cmd.SecureKey }
                ];

                const string sql = @"
                    SELECT membership_unique_id, status, outcome
                    FROM create_membership(@session_unique_id, @connection_id, @secure_key)";

                await using NpgsqlCommand command = CreateCommand(conn, sql, parameters);
                await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();

                if (!await reader.ReadAsync())
                {
                    return Result<MembershipQueryRecord, ShieldFailure>.Err(
                        ShieldFailure.DataAccess("Stored procedure create_membership returned no results."));
                }

                int membershipIdOrdinal = reader.GetOrdinal("membership_unique_id");
                int statusOrdinal = reader.GetOrdinal("status");
                int outcomeOrdinal = reader.GetOrdinal("outcome");

                Guid? membershipId = reader.IsDBNull(membershipIdOrdinal) ? null : reader.GetGuid(membershipIdOrdinal);
                string? statusStr = reader.IsDBNull(statusOrdinal) ? null : reader.GetString(statusOrdinal);
                string outcome = reader.GetString(outcomeOrdinal);

                Membership.Types.MembershipStatus status = statusStr switch
                {
                    "active" => Membership.Types.MembershipStatus.Active,
                    "inactive" => Membership.Types.MembershipStatus.Inactive,
                    _ => throw new InvalidOperationException($"Unknown membership status: {statusStr}")
                };

                return (membershipId, outcome) switch
                {
                    (Guid id, "created" or "membership_already_exists") => Result<MembershipQueryRecord, ShieldFailure>
                        .Ok(
                            new MembershipQueryRecord
                            {
                                UniqueIdentifier = id,
                                Status = status
                            }),
                    (null, var err) => Result<MembershipQueryRecord, ShieldFailure>.Err(
                        ShieldFailure.InvalidInput($"Membership creation failed: {err}")),
                    _ => Result<MembershipQueryRecord, ShieldFailure>.Err(
                        ShieldFailure.DataAccess($"Unexpected outcome: {outcome}"))
                };
            },
            "create membership");
    }
}