using Akka.Actor;
using Ecliptix.Domain.Memberships.Events;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.Utilities;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;
using Microsoft.Extensions.Logging;
using Npgsql;
using NpgsqlTypes;

namespace Ecliptix.Domain.Memberships.Persistors;

public class VerificationFlowPersistorActor : VerificationFlowPersistorBase
{
    public VerificationFlowPersistorActor(
        NpgsqlDataSource dataSource,
        ILogger<VerificationFlowPersistorActor> logger)
        : base(dataSource, logger)
    {
        Become(Ready);
    }

    public static Props Build(NpgsqlDataSource dataSource,
        ILogger<VerificationFlowPersistorActor> logger) =>
        Props.Create(() => new VerificationFlowPersistorActor(dataSource, logger));

    private void Ready()
    {
        ReceiveAsync<CreateVerificationFlowActorEvent>(HandleCreateVerificationFlow);
        ReceiveAsync<GetVerificationFlowActorEvent>(HandleGetVerificationFlow);
        ReceiveAsync<UpdateVerificationFlowStatusActorEvent>(HandleUpdateVerificationFlowStatus);
        ReceiveAsync<EnsurePhoneNumberActorEvent>(HandleEnsurePhoneNumber);
        ReceiveAsync<GetPhoneNumberActorEvent>(HandleGetPhoneNumber);
        ReceiveAsync<CreateOtpActorEvent>(HandleCreateOtp);
        ReceiveAsync<UpdateOtpStatusActorEvent>(HandleUpdateOtpStatus);
    }

    private async Task HandleUpdateOtpStatus(UpdateOtpStatusActorEvent cmd) =>
        await ExecuteWithConnection(
            async conn =>
            {
                NpgsqlParameter[] parameters =
                [
                    new(Parameters.OtpUniqueId, NpgsqlDbType.Uuid) { Value = cmd.OtpIdentified },
                    new(Parameters.Status, NpgsqlDbType.Varchar) { Value = cmd.Status.ToString().ToLowerInvariant() }
                ];

                await using NpgsqlCommand command = CreateCommand(conn, Queries.UpdateOtpStatus, parameters);
                await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();

                if (await reader.ReadAsync())
                {
                    bool success = reader.GetBoolean(0);
                    string message = reader.GetString(1);

                    return success
                        ? Result<Unit, VerificationFlowFailure>.Ok(Unit.Value)
                        : Result<Unit, VerificationFlowFailure>.Err(
                            VerificationFlowFailure.PersistorAccess(message));
                }

                return Result<Unit, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.NoResultReturned));
            }, OperationNames.UpdateOtpStatus);


    private async Task HandleGetPhoneNumber(GetPhoneNumberActorEvent cmd) =>
        await ExecuteWithConnection(
            async conn =>
            {
                NpgsqlParameter[] parameters =
                [
                    new(Parameters.PhoneUniqueId, NpgsqlDbType.Uuid) { Value = cmd.PhoneNumberIdentifier }
                ];

                await using NpgsqlCommand command = CreateCommand(conn, Queries.GetPhoneNumber, parameters);
                await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();

                if (!await reader.ReadAsync())
                {
                    return Result<PhoneNumberQueryRecord, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.NotFound(VerificationFlowMessageKeys.PhoneNotFound));
                }

                string phoneNumber = reader.GetString(0);
                Option<string> region = reader.IsDBNull(1)
                    ? Option<string>.None
                    : Option<string>.Some(reader.GetString(1));

                return Result<PhoneNumberQueryRecord, VerificationFlowFailure>.Ok(
                    new PhoneNumberQueryRecord(phoneNumber, region)
                    {
                        UniqueIdentifier = cmd.PhoneNumberIdentifier
                    });
            }, OperationNames.GetPhoneNumber);

    private async Task HandleCreateVerificationFlow(CreateVerificationFlowActorEvent cmd) =>
        await ExecuteWithConnection(
            async conn =>
            {
                NpgsqlParameter[] parameters =
                [
                    new(Parameters.AppDeviceId, NpgsqlDbType.Uuid) { Value = cmd.AppDeviceIdentifier },
                    new(Parameters.PhoneUniqueId, NpgsqlDbType.Uuid) { Value = cmd.PhoneNumberIdentifier },
                    new(Parameters.Purpose, NpgsqlDbType.Varchar) { Value = cmd.Purpose.ToString().ToLowerInvariant() },
                    new(Parameters.ExpiresAt, NpgsqlDbType.TimestampTz) { Value = cmd.ExpiresAt },
                    new(Parameters.ConnectId, NpgsqlDbType.Bigint) { Value = (long)cmd.ConnectId }
                ];

                await using NpgsqlCommand command = CreateCommand(conn, Queries.CreateVerificationFlow, parameters);
                await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();

                if (!await reader.ReadAsync())
                {
                    return Result<Guid, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.NoResultReturned));
                }

                Option<Guid> identifier = reader.IsDBNull(0)
                    ? Option<Guid>.None
                    : Option<Guid>.Some(reader.GetGuid(0));
                string outcome = reader.GetString(1);

                return outcome switch
                {
                    VerificationFlowMessageKeys.PhoneNotFound => Result<Guid, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.NotFound(VerificationFlowMessageKeys.PhoneNotFound)),

                    VerificationFlowMessageKeys.ConflictUnresolved => Result<Guid, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.Conflict(VerificationFlowMessageKeys.VerificationFlowConflict)),

                    VerificationFlowMessageKeys.Created => identifier.HasValue
                        ? Result<Guid, VerificationFlowFailure>.Ok(identifier.Value)
                        : Result<Guid, VerificationFlowFailure>.Err(
                            VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.UnexpectedOutcome)),

                    VerificationFlowMessageKeys.ExistingSessionReusedAndUpdated or
                        VerificationFlowMessageKeys.ConflictResolvedToExisting => identifier.HasValue
                            ? Result<Guid, VerificationFlowFailure>.Ok(identifier.Value)
                            : Result<Guid, VerificationFlowFailure>.Err(
                                VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.UnexpectedOutcome)),

                    _ => Result<Guid, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.PersistorAccess(
                            $"{VerificationFlowMessageKeys.UnexpectedOutcome}: {outcome}"))
                };
            }, OperationNames.CreateVerificationSession);


    private async Task HandleGetVerificationFlow(GetVerificationFlowActorEvent cmd) =>
        await ExecuteWithConnection(
            async conn =>
            {
                NpgsqlParameter[] parameters =
                [
                    new(Parameters.AppDeviceId, NpgsqlDbType.Uuid) { Value = cmd.DeviceId },
                    new(Parameters.PhoneUniqueId, NpgsqlDbType.Uuid) { Value = cmd.PhoneNumberIdentifier },
                    new(Parameters.Purpose, NpgsqlDbType.Varchar) { Value = cmd.Purpose.ToString().ToLowerInvariant() }
                ];
                return await ReadSessionQueryRecord(conn, parameters);
            }, OperationNames.GetVerificationSession);

    private async Task HandleUpdateVerificationFlowStatus(UpdateVerificationFlowStatusActorEvent cmd) =>
        await ExecuteWithConnection(
            async conn =>
            {
                NpgsqlParameter[] parameters =
                [
                    new(Parameters.SessionUniqueId, NpgsqlDbType.Uuid) { Value = cmd.FlowIdentifier },
                    new(Parameters.Status, NpgsqlDbType.Varchar) { Value = cmd.Status.ToString().ToLowerInvariant() }
                ];

                await using NpgsqlCommand command = CreateCommand(conn, Queries.UpdateSessionStatus, parameters);
                await command.ExecuteNonQueryAsync();
                return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
            }, OperationNames.UpdateSessionStatus);


    private async Task HandleCreateOtp(CreateOtpActorEvent cmd) =>
        await ExecuteWithConnection(
            async conn =>
            {
                NpgsqlParameter[] parameters =
                [
                    new(Parameters.SessionId, NpgsqlDbType.Uuid) { Value = cmd.OtpRecord.SessionIdentifier },
                    new(Parameters.OtpHash, NpgsqlDbType.Varchar) { Value = cmd.OtpRecord.OtpHash },
                    new(Parameters.OtpSalt, NpgsqlDbType.Varchar) { Value = cmd.OtpRecord.OtpSalt },
                    new(Parameters.ExpiresAt, NpgsqlDbType.TimestampTz) { Value = cmd.OtpRecord.ExpiresAt },
                    new(Parameters.Status, NpgsqlDbType.Varchar)
                        { Value = cmd.OtpRecord.Status.ToString().ToLowerInvariant() }
                ];

                await using NpgsqlCommand command = CreateCommand(conn, Queries.CreateOtp, parameters);
                await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();

                if (!await reader.ReadAsync())
                {
                    return Result<CreateOtpRecordResult, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.DataAccess));
                }

                Option<Guid> otpUniqueId = reader.IsDBNull(0)
                    ? Option<Guid>.None
                    : Option<Guid>.Some(reader.GetGuid(0));
                string outcome = reader.GetString(1);

                return outcome switch
                {
                    VerificationFlowMessageKeys.Created => otpUniqueId.HasValue
                        ? Result<CreateOtpRecordResult, VerificationFlowFailure>.Ok(
                            new CreateOtpRecordResult(otpUniqueId.Value))
                        : Result<CreateOtpRecordResult, VerificationFlowFailure>.Err(
                            VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.UnexpectedOutcome)),

                    VerificationFlowMessageKeys.VerificationFlowNotFound => Result<CreateOtpRecordResult,
                            VerificationFlowFailure>
                        .Err(
                            VerificationFlowFailure.NotFound(VerificationFlowMessageKeys.VerificationFlowNotFound)),

                    VerificationFlowMessageKeys.OtpMaxAttemptsReached =>
                        Result<CreateOtpRecordResult, VerificationFlowFailure>.Err(
                            VerificationFlowFailure.OtpMaxAttemptsReached(VerificationFlowMessageKeys
                                .OtpMaxAttemptsReached)),

                    _ => Result<CreateOtpRecordResult, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.OtpGenerationFailed(
                            $"{VerificationFlowMessageKeys.UnexpectedOutcome}: {outcome}"))
                };
            }, OperationNames.CreateOtpRecord);


    private async Task HandleEnsurePhoneNumber(EnsurePhoneNumberActorEvent cmd) =>
        await ExecuteWithConnection(
            async conn =>
            {
                NpgsqlParameter[] parameters =
                [
                    new(Parameters.PhoneNumberString, NpgsqlDbType.Varchar) { Value = cmd.PhoneNumber },
                    new(Parameters.Region, NpgsqlDbType.Varchar) { Value = (object?)cmd.RegionCode ?? DBNull.Value }
                ];

                await using NpgsqlCommand command = CreateCommand(conn, Queries.EnsurePhoneNumber, parameters);
                await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();

                if (!await reader.ReadAsync())
                {
                    return Result<Guid, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.NoResultReturned));
                }

                Option<Guid> uniqueIdOpt = reader.IsDBNull(0)
                    ? Option<Guid>.None
                    : Option<Guid>.Some(reader.GetGuid(0));

                string outcome = reader.GetString(1);
                bool success = reader.GetBoolean(2);

                if (!success)
                {
                    return outcome switch
                    {
                        VerificationFlowMessageKeys.AppDeviceInvalidId => Result<Guid, VerificationFlowFailure>.Err(
                            VerificationFlowFailure.Validation(VerificationFlowMessageKeys
                                .AppDeviceInvalidId)),

                        VerificationFlowMessageKeys.AppDeviceCreatedButInvalidId =>
                            Result<Guid, VerificationFlowFailure>.Err(
                                VerificationFlowFailure.Validation(VerificationFlowMessageKeys
                                    .AppDeviceCreatedButInvalidId)),

                        _ when IsKnownEnsurePhoneNumberErrorKey(outcome) =>
                            Result<Guid, VerificationFlowFailure>.Err(
                                VerificationFlowFailure
                                    .PhoneNumberInvalid(
                                        outcome)),

                        _ => Result<Guid, VerificationFlowFailure>.Err(
                            VerificationFlowFailure.PhoneNumberInvalid(VerificationFlowMessageKeys
                                .PhoneNumberInvalid))
                    };
                }

                if (!uniqueIdOpt.HasValue)
                {
                    return Result<Guid, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.UnexpectedOutcome));
                }

                return Result<Guid, VerificationFlowFailure>.Ok(uniqueIdOpt.Value);
            }, OperationNames.EnsurePhoneNumber);

    private static bool IsKnownEnsurePhoneNumberErrorKey(string outcomeKey) =>
        outcomeKey is VerificationFlowMessageKeys.AppDeviceInvalidId or
            VerificationFlowMessageKeys.AppDeviceCreatedButInvalidId or
            VerificationFlowMessageKeys.PhoneNumberInvalid;

    private static async Task<Result<Option<VerificationFlowQueryRecord>, VerificationFlowFailure>>
        ReadSessionQueryRecord(NpgsqlConnection conn, NpgsqlParameter[] parameters)
    {
        await using NpgsqlCommand command = CreateCommand(conn, Queries.GetVerificationFlow, parameters);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();

        if (!await reader.ReadAsync())
        {
            return Result<Option<VerificationFlowQueryRecord>, VerificationFlowFailure>.Ok(
                Option<VerificationFlowQueryRecord>.None);
        }

        Option<OtpQueryRecord> otpActive = Option<OtpQueryRecord>.None;
        if (!reader.IsDBNull(ColumnIndices.OtpUniqueId))
        {
            otpActive = Option<OtpQueryRecord>.Some(new OtpQueryRecord
            {
                UniqueIdentifier = reader.GetGuid(ColumnIndices.OtpUniqueId),
                SessionIdentifier = reader.GetGuid(ColumnIndices.SessionUniqueId),
                OtpHash = reader.GetString(ColumnIndices.OtpHash),
                OtpSalt = reader.GetString(ColumnIndices.OtpSalt),
                ExpiresAt = reader.GetDateTime(ColumnIndices.OtpExpiresAt),
                Status = Enum.Parse<VerificationFlowStatus>(reader.GetString(ColumnIndices.OtpStatus), true)
            });
        }

        VerificationFlowQueryRecord record = new(
            reader.GetGuid(ColumnIndices.SessionUniqueId),
            reader.GetGuid(ColumnIndices.PhoneNumberUniqueId),
            reader.GetGuid(ColumnIndices.AppDeviceId),
            reader.IsDBNull(ColumnIndices.ConnectionId)
                ? 0
                : (uint)reader.GetInt64(ColumnIndices.ConnectionId))
        {
            ExpiresAt = reader.GetDateTime(ColumnIndices.ExpiresAt),
            Status = Enum.Parse<VerificationFlowStatus>(reader.GetString(ColumnIndices.Status), true),
            Purpose = Enum.Parse<VerificationPurpose>(reader.GetString(ColumnIndices.Purpose), true),
            OtpCount = reader.GetInt16(ColumnIndices.OtpCount),
            OtpActive = otpActive
        };

        return Result<Option<VerificationFlowQueryRecord>, VerificationFlowFailure>.Ok(
            Option<VerificationFlowQueryRecord>.Some(record));
    }
}