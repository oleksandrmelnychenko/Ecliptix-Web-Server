using Akka.Actor;
using Ecliptix.Domain.Memberships;
using Ecliptix.Domain.Persistors.QueryRecords;
using Ecliptix.Domain.Utilities;
using Npgsql;
using NpgsqlTypes;

namespace Ecliptix.Domain.Persistors;

// Command records
public record CreateVerificationSessionRecordCommand(VerificationSessionQueryRecord VerificationSessionQueryRecord);
public record GetVerificationSessionCommand(Guid DeviceId);
public record UpdateSessionStatusCommand(Guid SessionId, VerificationSessionStatus Status);
public record VerifyCodeCommand;

public class VerificationSessionPersistorActor : ReceiveActor
{
    private readonly NpgsqlDataSource _dataSource;

    // SQL query constants
    private const string CREATE_SESSION_SQL = "SELECT create_verification_session(@device_id, @code, @expires_at, @connect_id, @mobile, @stream_id)";
    private const string GET_SESSION_SQL = "SELECT connect_id, stream_id, mobile, device_id, code, expires_at, status FROM get_verification_session(@device_id)";
    private const string UPDATE_STATUS_SQL = "SELECT update_verification_session_status(@device_id, @status::verification_status)";

    // Parameter name constants (for reused parameters)
    private const string DEVICE_ID_PARAM = "device_id";
    private const string STATUS_PARAM = "status";

    public VerificationSessionPersistorActor(NpgsqlDataSource dataSource)
    {
        _dataSource = dataSource;
        Become(Ready);
    }

    public static Props Build(NpgsqlDataSource dataSource) => Props.Create(() => new VerificationSessionPersistorActor(dataSource));

    private void Ready()
    {
        ReceiveAsync<CreateVerificationSessionRecordCommand>(HandleCreateMembershipVerificationSessionRecord);
        ReceiveAsync<GetVerificationSessionCommand>(HandleGetVerificationSession);
        ReceiveAsync<UpdateSessionStatusCommand>(HandleUpdateSessionStatus);
        ReceiveAsync<VerifyCodeCommand>(HandleVerifyCode);
    }

    private async Task HandleCreateMembershipVerificationSessionRecord(CreateVerificationSessionRecordCommand cmd)
    {
        await ExecuteWithConnection(
            async conn =>
            {
                VerificationSessionQueryRecord record = cmd.VerificationSessionQueryRecord;
                NpgsqlParameter[] parameters =
                [
                    new(DEVICE_ID_PARAM, NpgsqlDbType.Uuid) { Value = record.AppDeviceUniqueRec },
                    new("code", NpgsqlDbType.Varchar, 6) { Value = record.Code },
                    new("expires_at", NpgsqlDbType.TimestampTz) { Value = record.ExpiresAt },
                    new("connect_id", NpgsqlDbType.Bigint) { Value = (long)record.ConnectId },
                    new("mobile", NpgsqlDbType.Varchar, 20) { Value = record.Mobile },
                    new("stream_id", NpgsqlDbType.Uuid) { Value = record.StreamId }
                ];
                await using NpgsqlCommand command = CreateCommand(conn, CREATE_SESSION_SQL, parameters);
                object? result = await command.ExecuteScalarAsync();
                return result == null || result == DBNull.Value
                    ? Result<Unit, ShieldFailure>.Err(ShieldFailure.DataAccess("Failed to create verification session: conflicting pending session exists."))
                    : Result<Unit, ShieldFailure>.Ok(Unit.Value);
            },
            "session creation"
        );
    }

    private async Task HandleGetVerificationSession(GetVerificationSessionCommand cmd)
    {
        await ExecuteWithConnection(
            async conn =>
            {
                NpgsqlParameter[] parameters = [new(DEVICE_ID_PARAM, NpgsqlDbType.Uuid) { Value = cmd.DeviceId }
                ];
                await using NpgsqlCommand command = CreateCommand(conn, GET_SESSION_SQL, parameters);
                await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
                var record = await reader.ReadAsync()
                    ? new VerificationSessionQueryRecord(
                        ConnectId: (uint)reader.GetInt64(0),
                        StreamId: reader.GetGuid(1),
                        Mobile: reader.IsDBNull(2) ? null : reader.GetString(2),
                        AppDeviceUniqueRec: reader.GetGuid(3),
                        Code: reader.GetString(4)
                    )
                    {
                        ExpiresAt = reader.GetDateTime(5),
                        Status = Enum.Parse<VerificationSessionStatus>(reader.GetString(6), ignoreCase: true)
                    }
                    : VerificationSessionQueryRecord.Empty;
                return Result<VerificationSessionQueryRecord, ShieldFailure>.Ok(record);
            },
            "session retrieval"
        );
    }

    private async Task HandleUpdateSessionStatus(UpdateSessionStatusCommand cmd)
    {
        await ExecuteWithConnection(
            async conn =>
            {
                NpgsqlParameter[] parameters =
                [
                    new(DEVICE_ID_PARAM, NpgsqlDbType.Uuid) { Value = cmd.SessionId },
                    new(STATUS_PARAM, NpgsqlDbType.Varchar) { Value = cmd.Status.ToString().ToLower() }
                ];
                await using NpgsqlCommand command = CreateCommand(conn, UPDATE_STATUS_SQL, parameters);
                await command.ExecuteNonQueryAsync();
                return Result<Unit, ShieldFailure>.Ok(Unit.Value);
            },
            "session status update"
        );
    }

    private async Task HandleVerifyCode(VerifyCodeCommand cmd)
    {
        await ExecuteWithConnection(
            async conn =>
            {
                // Placeholder for verification logic
                return Result<Unit, ShieldFailure>.Ok(Unit.Value);
            },
            "code verification"
        );
    }

    private async Task ExecuteWithConnection<T>(
        Func<NpgsqlConnection, Task<Result<T, ShieldFailure>>> operation,
        string operationName)
    {
        try
        {
            await using NpgsqlConnection conn = _dataSource.CreateConnection();
            await conn.OpenAsync();
            Result<T, ShieldFailure> result = await operation(conn);
            Sender.Tell(result);
        }
        catch (NpgsqlException dbEx)
        {
            Sender.Tell(Result<T, ShieldFailure>.Err(
                ShieldFailure.DataAccess($"Database error during {operationName}: {dbEx.Message}", dbEx)));
        }
        catch (Exception ex)
        {
            Sender.Tell(Result<T, ShieldFailure>.Err(
                ShieldFailure.Generic($"Unexpected error during {operationName}: {ex.Message}", ex)));
        }
    }

    private static NpgsqlCommand CreateCommand(NpgsqlConnection connection, string sql, params NpgsqlParameter[] parameters)
    {
        NpgsqlCommand command = new(sql, connection);
        command.Parameters.AddRange(parameters);
        return command;
    }
}