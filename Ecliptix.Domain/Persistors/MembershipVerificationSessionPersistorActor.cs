using Akka.Actor;
using Ecliptix.Domain.Memberships;
using Ecliptix.Domain.Persistors.QueryRecords;
using Ecliptix.Domain.Utilities;
using Npgsql;
using NpgsqlTypes;
using System;
using System.Threading.Tasks;

namespace Ecliptix.Domain.Persistors;

public record CreateMembershipVerificationSessionRecordCommand(
    VerificationSessionQueryRecord VerificationSessionQueryRecord);

public record GetVerificationSessionCommand(Guid DeviceId);

public class MembershipVerificationSessionPersistorActor : ReceiveActor
{
    private readonly NpgsqlDataSource _npgsqlDataSource;

    public MembershipVerificationSessionPersistorActor(NpgsqlDataSource npgsqlDataSource)
    {
        _npgsqlDataSource = npgsqlDataSource;

        Become(Ready);
    }

    public static Props Build(NpgsqlDataSource npgsqlDataSource) =>
        Props.Create(() => new MembershipVerificationSessionPersistorActor(npgsqlDataSource));

    private void Ready()
    {
        ReceiveAsync<CreateMembershipVerificationSessionRecordCommand>(HandleCreateMembershipVerificationSessionRecord);
        ReceiveAsync<GetVerificationSessionCommand>(HandleGetVerificationSession);
    }

    private async Task HandleCreateMembershipVerificationSessionRecord(
        CreateMembershipVerificationSessionRecordCommand cmd)
    {
        try
        {
            await using NpgsqlConnection connection = _npgsqlDataSource.CreateConnection();
            await connection.OpenAsync();
            await using NpgsqlCommand command = new(
                "SELECT create_verification_session(@device_id, @code, @expires_at, @connect_id, @mobile, @stream_id)",
                connection);

            VerificationSessionQueryRecord record = cmd.VerificationSessionQueryRecord;
            command.Parameters.Add(new NpgsqlParameter("device_id", NpgsqlDbType.Uuid)
                { Value = record.AppDeviceUniqueRec });
            command.Parameters.Add(new NpgsqlParameter("code", NpgsqlDbType.Varchar, 6)
                { Value = record.Code });
            command.Parameters.Add(new NpgsqlParameter("expires_at", NpgsqlDbType.TimestampTz)
                { Value = record.ExpiresAt });
            command.Parameters.Add(new NpgsqlParameter("connect_id", NpgsqlDbType.Bigint)
                { Value = (long)record.ConnectId });
            command.Parameters.Add(new NpgsqlParameter("mobile", NpgsqlDbType.Varchar, 20)
                { Value = record.Mobile });
            command.Parameters.Add(new NpgsqlParameter("stream_id", NpgsqlDbType.Uuid)
                { Value = record.StreamId });

            object? result = await command.ExecuteScalarAsync();

            if (result == null || result == DBNull.Value)
            {
                Sender.Tell(Result<Unit, ShieldFailure>.Err(
                    ShieldFailure.DataAccess(
                        "Failed to create verification session: conflicting pending session exists.")));
            }

            Sender.Tell(Result<Unit, ShieldFailure>.Ok(Unit.Value));
        }
        catch (NpgsqlException dbEx)
        {
            Sender.Tell(Result<VerificationSessionQueryRecord, ShieldFailure>.Err(
                ShieldFailure.DataAccess($"Database error during session retrieval: {dbEx.Message}", dbEx)));
        }
        catch (Exception ex)
        {
            Sender.Tell(Result<VerificationSessionQueryRecord, ShieldFailure>.Err(
                ShieldFailure.Generic($"Unexpected error during session retrieval: {ex.Message}", ex)));
        }
    }

    private async Task HandleGetVerificationSession(
        GetVerificationSessionCommand cmd)
    {
        try
        {
            await using NpgsqlConnection connection = _npgsqlDataSource.CreateConnection();
            await connection.OpenAsync();
            await using NpgsqlCommand command = new(
                "SELECT connect_id, stream_id, mobile, device_id, code, expires_at, status " +
                "FROM get_verification_session(@device_id)",
                connection);

            command.Parameters.Add(new NpgsqlParameter("device_id", NpgsqlDbType.Uuid) { Value = cmd.DeviceId });

            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
            if (await reader.ReadAsync())
            {
                VerificationSessionQueryRecord record = new(
                    ConnectId: (uint)reader.GetInt64(0),
                    StreamId: reader.GetGuid(1),
                    Mobile: reader.IsDBNull(2) ? null : reader.GetString(2),
                    AppDeviceUniqueRec: reader.GetGuid(3),
                    Code: reader.GetString(4)
                )
                {
                    ExpiresAt = reader.GetDateTime(5),
                    Status = Enum.Parse<MembershipVerificationSessionStatus>(reader.GetString(6), ignoreCase: true)
                };
                Sender.Tell(Result<VerificationSessionQueryRecord, ShieldFailure>.Ok(record));
            }

            Sender.Tell(Result<VerificationSessionQueryRecord, ShieldFailure>.Ok(VerificationSessionQueryRecord.Empty));
        }
        catch (NpgsqlException dbEx)
        {
            Sender.Tell(Result<VerificationSessionQueryRecord, ShieldFailure>.Err(
                ShieldFailure.DataAccess($"Database error during session retrieval: {dbEx.Message}", dbEx)));
        }
        catch (Exception ex)
        {
            Sender.Tell(Result<VerificationSessionQueryRecord, ShieldFailure>.Err(
                ShieldFailure.Generic($"Unexpected error during session retrieval: {ex.Message}", ex)));
        }
    }
}