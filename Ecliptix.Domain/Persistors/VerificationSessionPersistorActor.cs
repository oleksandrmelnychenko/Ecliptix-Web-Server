using Akka.Actor;
using Ecliptix.Domain.Memberships;
using Ecliptix.Domain.Persistors.QueryRecords;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Authentication;
using Npgsql;
using NpgsqlTypes;

namespace Ecliptix.Domain.Persistors;

public record EnsurePhoneNumberActorCommand(
    string PhoneNumber,
    string? RegionCode,
    CustomPhoneNumberType PhoneType,
    uint ConnectId);

public record CreateVerificationSessionRecordCommand(
    Guid PhoneNumberIdentifier,
    Guid AppDeviceIdentifier,
    VerificationPurpose Purpose,
    DateTime ExpiresAt,
    uint ConnectId);

public record GetVerificationSessionCommand(
    Guid DeviceId,
    Guid PhoneNumberIdentifier,
    VerificationPurpose Purpose);

public record GetPhoneNumberActorCommand(Guid PhoneNumberIdentifier);

public record UpdateVerificationSessionStatusCommand(Guid SessionId, VerificationSessionStatus Status);

public record CreateOtpRecordCommand(OtpQueryRecord OtpRecord);

public record VerifyCodeWithSessionCommand(
    Guid SessionIdentifier,
    string Code,
    VerificationPurpose VerificationPurpose,
    uint ConnectId);

public class VerificationSessionPersistorActor : ReceiveActor
{
    private readonly NpgsqlDataSource _dataSource;

    private const string GetSessionSql =
        "SELECT session_unique_id, phone_number_unique_id_out, connection_id, app_device_id_out, phone_number_out, phone_region_out, phone_type_out, expires_at_out, status_out, purpose_out, otp_count_out FROM get_verification_session(@app_device_id, @phone_unique_id, @purpose::verification_purpose)";

    private const string CreateSessionSql =
        "SELECT session_unique_id, outcome FROM create_verification_session(@app_device_id, @phone_unique_id, @purpose::verification_purpose, @expires_at, @connect_id)";

    private const string UpdateStatusSql =
        "SELECT update_verification_session_status(@session_unique_id, @status::verification_status)";

    private const string VerifyCodeSql =
        "SELECT verify_code(@session_unique_id, @submitted_code, @max_attempts)";

    private const string AppDeviceIdParam = "app_device_id";
    private const string PhoneNumberIdentifierParam = "phone_unique_id";
    private const string SessionUniqueIdParam = "session_unique_id";
    private const string CodeParam = "code";
    private const string PurposeParam = "purpose";
    private const string StatusParam = "status";

    public VerificationSessionPersistorActor(NpgsqlDataSource dataSource)
    {
        _dataSource = dataSource;
        Become(Ready);
    }

    public static Props Build(NpgsqlDataSource dataSource) =>
        Props.Create(() => new VerificationSessionPersistorActor(dataSource));

    private void Ready()
    {
        ReceiveAsync<CreateVerificationSessionRecordCommand>(HandleCreateVerificationSessionRecord);
        ReceiveAsync<GetVerificationSessionCommand>(HandleGetVerificationSession);
        ReceiveAsync<UpdateVerificationSessionStatusCommand>(HandleUpdateSessionStatus);
        ReceiveAsync<VerifyCodeWithSessionCommand>(HandleVerifyCodeWithSession);
        ReceiveAsync<EnsurePhoneNumberActorCommand>(HandleEnsurePhoneNumberCommand);
        ReceiveAsync<GetPhoneNumberActorCommand>(HandleGetPhoneNumberCommand);
        ReceiveAsync<CreateOtpRecordCommand>(HandleCreateOtpRecord);
    }

    private async Task HandleGetPhoneNumberCommand(GetPhoneNumberActorCommand cmd)
    {
        await ExecuteWithConnection(
            async conn =>
            {
                const string sql = @"
                        SELECT phone_number, region, type
                        FROM get_phone_number(@phone_unique_id);
                    ";

                NpgsqlParameter[] parameters =
                [
                    new("phone_unique_id", NpgsqlDbType.Uuid) { Value = cmd.PhoneNumberIdentifier }
                ];

                await using NpgsqlCommand command = CreateCommand(conn, sql, parameters);
                await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();

                if (!await reader.ReadAsync())
                {
                    return Result<PhoneNumberQueryRecord, ShieldFailure>.Err(
                        ShieldFailure.DataAccess("Phone number not found."));
                }

                string phoneNumber = reader.GetString(0);
                string? region = reader.IsDBNull(1) ? null : reader.GetString(1);
                CustomPhoneNumberType type = Enum.Parse<CustomPhoneNumberType>(reader.GetString(2), true);

                return Result<PhoneNumberQueryRecord, ShieldFailure>.Ok(
                    new PhoneNumberQueryRecord(phoneNumber, region, type)
                    {
                        UniqueIdentifier = cmd.PhoneNumberIdentifier
                    });
            },
            "get phone number");
    }

    private async Task HandleCreateVerificationSessionRecord(CreateVerificationSessionRecordCommand cmd)
    {
        await ExecuteWithConnection(
            async conn =>
            {
                NpgsqlParameter[] parameters =
                [
                    new("app_device_id", NpgsqlDbType.Uuid) { Value = cmd.AppDeviceIdentifier },
                    new(PhoneNumberIdentifierParam, NpgsqlDbType.Uuid) { Value = cmd.PhoneNumberIdentifier },
                    new(PurposeParam, NpgsqlDbType.Varchar) { Value = cmd.Purpose.ToString().ToLowerInvariant() },
                    new("expires_at", NpgsqlDbType.TimestampTz) { Value = cmd.ExpiresAt },
                    new("connect_id", NpgsqlDbType.Bigint) { Value = (long)cmd.ConnectId }
                ];

                await using NpgsqlCommand command = CreateCommand(conn, CreateSessionSql, parameters);
                await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();

                if (!await reader.ReadAsync())
                {
                    return Result<Guid, ShieldFailure>.Err(
                        ShieldFailure.DataAccess("Failed to create verification session: no result."));
                }

                Guid? verificationSessionIdentifier = reader.IsDBNull(0) ? null : reader.GetGuid(0);
                string outcome = reader.GetString(1);

                if (!verificationSessionIdentifier.HasValue || outcome is "phone_not_found" or "conflict_unresolved")
                {
                    return Result<Guid, ShieldFailure>.Err(
                        ShieldFailure.DataAccess($"Failed to create verification session: {outcome}"));
                }

                return Result<Guid, ShieldFailure>.Ok(verificationSessionIdentifier.Value);
            },
            "session creation");
    }

    private async Task HandleGetVerificationSession(GetVerificationSessionCommand cmd)
    {
        await ExecuteWithConnection(
            conn =>
            {
                NpgsqlParameter[] parameters =
                [
                    new(AppDeviceIdParam, NpgsqlDbType.Uuid) { Value = cmd.DeviceId },
                    new(PhoneNumberIdentifierParam, NpgsqlDbType.Uuid) { Value = cmd.PhoneNumberIdentifier },
                    new(PurposeParam, NpgsqlDbType.Varchar) { Value = cmd.Purpose.ToString().ToLowerInvariant() }
                ];
                return ReadSessionQueryRecord(conn, parameters);
            },
            "session retrieval");
    }

    private async Task HandleUpdateSessionStatus(UpdateVerificationSessionStatusCommand cmd)
    {
        await ExecuteWithConnection(
            async conn =>
            {
                NpgsqlParameter[] parameters =
                [
                    new(SessionUniqueIdParam, NpgsqlDbType.Uuid) { Value = cmd.SessionId },
                    new(StatusParam, NpgsqlDbType.Varchar) { Value = cmd.Status.ToString().ToLowerInvariant() }
                ];

                await using NpgsqlCommand command = CreateCommand(conn, UpdateStatusSql, parameters);
                await command.ExecuteNonQueryAsync();
                return Result<Unit, ShieldFailure>.Ok(Unit.Value);
            },
            "session status update");
    }

    private async Task HandleCreateOtpRecord(CreateOtpRecordCommand cmd)
    {
        await ExecuteWithConnection(
            async conn =>
            {
                const string sql = @"
                SELECT otp_unique_id, outcome FROM insert_otp_record(@session_unique_id, @otp_hash, @otp_salt, @expires_at, @status::verification_status)";
                NpgsqlParameter[] parameters =
                [
                    new("session_unique_id", NpgsqlDbType.Uuid) { Value = cmd.OtpRecord.SessionIdentifier },
                    new("otp_hash", NpgsqlDbType.Varchar) { Value = cmd.OtpRecord.OtpHash },
                    new("otp_salt", NpgsqlDbType.Varchar) { Value = cmd.OtpRecord.OtpSalt },
                    new("expires_at", NpgsqlDbType.TimestampTz) { Value = cmd.OtpRecord.ExpiresAt },
                    new("status", NpgsqlDbType.Varchar) { Value = cmd.OtpRecord.Status.ToString().ToLowerInvariant() }
                ];

                await using NpgsqlCommand command = CreateCommand(conn, sql, parameters);
                await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
                if (await reader.ReadAsync())
                {
                    Guid otpUniqueId = reader.GetGuid(0);
                    string outcome = reader.GetString(1);
                    if (outcome == "created")
                    {
                        return Result<Guid, ShieldFailure>.Ok(otpUniqueId);
                    }

                    return Result<Guid, ShieldFailure>.Err(ShieldFailure.Generic($"OTP insertion failed: {outcome}"));
                }

                return Result<Guid, ShieldFailure>.Err(ShieldFailure.DataAccess("Failed to insert OTP record."));
            },
            "insert OTP record");
    }

    private async Task HandleVerifyCodeWithSession(VerifyCodeWithSessionCommand cmd)
    {
        await ExecuteWithConnection(
            async conn =>
            {
                NpgsqlParameter[] parameters =
                [
                    new("session_unique_id", NpgsqlDbType.Uuid) { Value = cmd.SessionIdentifier },
                    new("submitted_code", NpgsqlDbType.Varchar) { Value = cmd.Code },
                    new("max_attempts", NpgsqlDbType.Smallint) { Value = 5 }
                ];

                await using NpgsqlCommand command = CreateCommand(conn, VerifyCodeSql, parameters);
                string outcome = (string)(await command.ExecuteScalarAsync() ?? "failed");

                if (outcome == "verified")
                {
                    return Result<Unit, ShieldFailure>.Ok(Unit.Value);
                }

                return Result<Unit, ShieldFailure>.Err(
                    ShieldFailure.Generic($"Code verification failed: {outcome}"));
            },
            "code verification");
    }

    private async Task HandleEnsurePhoneNumberCommand(EnsurePhoneNumberActorCommand cmd)
    {
        await ExecuteWithConnection(
            async conn =>
            {
                NpgsqlParameter[] parameters =
                [
                    new("phone_number_string", NpgsqlDbType.Varchar) { Value = cmd.PhoneNumber },
                    new("region", NpgsqlDbType.Varchar) { Value = (object?)cmd.RegionCode ?? DBNull.Value },
                    new("type", NpgsqlDbType.Varchar) { Value = cmd.PhoneType.ToString().ToLowerInvariant() }
                ];

                const string sql =
                    "SELECT ensure_phone_number(@phone_number_string, @region, @type::phone_number_type)";

                await using NpgsqlCommand command = CreateCommand(conn, sql, parameters);
                object? result = await command.ExecuteScalarAsync();

                if (result is not Guid guid)
                    return Result<Guid, ShieldFailure>.Err(
                        ShieldFailure.DataAccess("Failed to ensure phone number."));

                return Result<Guid, ShieldFailure>.Ok(guid);
            },
            "ensure phone number");
    }


    private static async Task<Result<Option<VerificationSessionQueryRecord>, ShieldFailure>> ReadSessionQueryRecord(
        NpgsqlConnection conn, NpgsqlParameter[] parameters)
    {
        await using NpgsqlCommand command = CreateCommand(conn, GetSessionSql, parameters);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();

        if (!await reader.ReadAsync())
            return Result<Option<VerificationSessionQueryRecord>, ShieldFailure>.Ok(
                Option<VerificationSessionQueryRecord>.None);

        VerificationSessionQueryRecord record = new(
            UniqueIdentifier: reader.GetGuid(0),
            PhoneNumberIdentifier: reader.GetGuid(1),
            AppDeviceIdentifier: reader.GetGuid(3),
            ConnectId: reader.IsDBNull(2) ? 0 : (uint)reader.GetInt64(2))
        {
            ExpiresAt = reader.GetDateTime(7),
            Purpose = Enum.Parse<VerificationPurpose>(reader.GetString(9), true)
        };

        return Result<Option<VerificationSessionQueryRecord>, ShieldFailure>.Ok(
            Option<VerificationSessionQueryRecord>.Some(record));
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

    private static NpgsqlCommand CreateCommand(NpgsqlConnection connection, string sql,
        params NpgsqlParameter[] parameters)
    {
        NpgsqlCommand command = new NpgsqlCommand(sql, connection);
        command.Parameters.AddRange(parameters);
        return command;
    }
}