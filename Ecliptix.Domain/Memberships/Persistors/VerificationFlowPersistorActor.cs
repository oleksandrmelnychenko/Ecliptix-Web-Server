using System.Data;
using System.Data.Common;
using Akka.Actor;
using Dapper;
using Ecliptix.Domain.DbConnectionFactory;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.QueryResults;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Logging;

namespace Ecliptix.Domain.Memberships.Persistors;

public class VerificationFlowPersistorActor : PersistorBase<VerificationFlowFailure>
{
    public VerificationFlowPersistorActor(
        IDbConnectionFactory connectionFactory)
        : base(connectionFactory)
    {
        Become(Ready);
    }

    public static Props Build(IDbConnectionFactory connectionFactory)
    {
        return Props.Create(() => new VerificationFlowPersistorActor(connectionFactory));
    }

    private void Ready()
    {
        Receive<InitiateFlowAndReturnStateActorEvent>(actorEvent =>
            ExecuteWithConnection(conn => InitiateFlowAsync(conn, actorEvent), "InitiateVerificationFlow")
                .PipeTo(Sender));
        Receive<RequestResendOtpActorEvent>(actorEvent =>
            ExecuteWithConnection(conn => RequestResendOtpAsync(conn, actorEvent), "RequestResendOtp").PipeTo(Sender));
        Receive<UpdateVerificationFlowStatusActorEvent>(actorEvent =>
            ExecuteWithConnection(conn => UpdateVerificationFlowStatusAsync(conn, actorEvent),
                    "UpdateVerificationFlowStatus")
                .PipeTo(Sender));
        Receive<EnsurePhoneNumberActorEvent>(actorEvent =>
            ExecuteWithConnection(conn => EnsurePhoneNumberAsync(conn, actorEvent), "EnsurePhoneNumber")
                .PipeTo(Sender));
        Receive<GetPhoneNumberActorEvent>(actorEvent =>
            ExecuteWithConnection(conn => GetPhoneNumberAsync(conn, actorEvent), "GetPhoneNumber").PipeTo(Sender));
        Receive<CreateOtpActorEvent>(actorEvent =>
            ExecuteWithConnection(conn => CreateOtpAsync(conn, actorEvent), "CreateOtp").PipeTo(Sender));
        Receive<UpdateOtpStatusActorEvent>(actorEvent =>
            ExecuteWithConnection(conn => UpdateOtpStatusAsync(conn, actorEvent), "UpdateOtpStatus").PipeTo(Sender));
    }

    private async Task<Result<VerificationFlowQueryRecord, VerificationFlowFailure>> InitiateFlowAsync(
        IDbConnection conn, InitiateFlowAndReturnStateActorEvent cmd)
    {
        DynamicParameters parameters = new();
        parameters.Add("@AppDeviceId", cmd.AppDeviceId);
        parameters.Add("@PhoneUniqueId", cmd.PhoneNumberId);
        parameters.Add("@Purpose", cmd.Purpose.ToString().ToLowerInvariant());
        parameters.Add("@ConnectionId", (long?)cmd.ConnectId);

        InitiateVerificationFlowResult? result = await conn.QuerySingleOrDefaultAsync<InitiateVerificationFlowResult>(
            "dbo.InitiateVerificationFlow",
            parameters,
            commandType: CommandType.StoredProcedure);

        if (result is null)
            return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(VerificationFlowFailure.NotFound());

        return result.Outcome switch
        {
            "phone_not_found" => Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.NotFound(result.Outcome)),
            "global_rate_limit_exceeded" => Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.RateLimitExceeded(result.Outcome)),
            _ => MapToVerificationFlowRecord(result)
        };
    }

    private async Task<Result<string, VerificationFlowFailure>> RequestResendOtpAsync(IDbConnection conn,
        RequestResendOtpActorEvent cmd)
    {
        var parameters = new { cmd.FlowUniqueId };
        RequestResendOtpResult result = await conn.QuerySingleAsync<RequestResendOtpResult>(
            "dbo.RequestResendOtp",
            parameters,
            commandType: CommandType.StoredProcedure
        );
        return Result<string, VerificationFlowFailure>.Ok(result.Outcome);
    }

    private async Task<Result<Unit, VerificationFlowFailure>> UpdateOtpStatusAsync(IDbConnection conn,
        UpdateOtpStatusActorEvent cmd)
    {
        UpdateOtpStatusResult result = await conn.QuerySingleAsync<UpdateOtpStatusResult>(
            "dbo.UpdateOtpStatus",
            new { OtpUniqueId = cmd.OtpIdentified, NewStatus = cmd.Status.ToString().ToLowerInvariant() },
            commandType: CommandType.StoredProcedure);

        return result.Success
            ? Result<Unit, VerificationFlowFailure>.Ok(Unit.Value)
            : Result<Unit, VerificationFlowFailure>.Err(VerificationFlowFailure.PersistorAccess(result.Message));
    }

    private async Task<Result<PhoneNumberQueryRecord, VerificationFlowFailure>> GetPhoneNumberAsync(IDbConnection conn,
        GetPhoneNumberActorEvent cmd)
    {
        PhoneNumberQueryRecord? result = await conn.QuerySingleOrDefaultAsync<PhoneNumberQueryRecord>(
            "SELECT * FROM dbo.GetPhoneNumber(@PhoneUniqueId)",
            new { PhoneUniqueId = cmd.PhoneNumberIdentifier });

        return result != null
            ? Result<PhoneNumberQueryRecord, VerificationFlowFailure>.Ok(result)
            : Result<PhoneNumberQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.NotFound(VerificationFlowMessageKeys.PhoneNotFound));
    }

    private async Task<Result<int, VerificationFlowFailure>> UpdateVerificationFlowStatusAsync(IDbConnection conn,
        UpdateVerificationFlowStatusActorEvent cmd)
    {
        DynamicParameters parameters = new();
        parameters.Add("@FlowUniqueId", cmd.FlowIdentifier);
        parameters.Add("@NewStatus", cmd.Status.ToString().ToLowerInvariant());
        parameters.Add("@rowsAffected", dbType: DbType.Int32, direction: ParameterDirection.ReturnValue);

        await conn.ExecuteAsync("dbo.UpdateVerificationFlowStatus", parameters,
            commandType: CommandType.StoredProcedure);

        return Result<int, VerificationFlowFailure>.Ok(parameters.Get<int>("@rowsAffected"));
    }

    private async Task<Result<CreateOtpResult, VerificationFlowFailure>> CreateOtpAsync(IDbConnection conn,
        CreateOtpActorEvent cmd)
    {
        var parameters = new
        {
            cmd.OtpRecord.FlowUniqueId,
            cmd.OtpRecord.OtpHash,
            cmd.OtpRecord.OtpSalt,
            cmd.OtpRecord.ExpiresAt,
            Status = cmd.OtpRecord.Status.ToString().ToLowerInvariant()
        };

        CreateOtpResult result = await conn.QuerySingleAsync<CreateOtpResult>(
            "dbo.InsertOtpRecord",
            parameters,
            commandType: CommandType.StoredProcedure);

        return result.Outcome switch
        {
            "created" => Result<CreateOtpResult, VerificationFlowFailure>.Ok(result),
            "flow_not_found_or_invalid" =>
                Result<CreateOtpResult, VerificationFlowFailure>.Err(VerificationFlowFailure.NotFound(result.Outcome)),
            "max_otp_attempts_reached" =>
                Result<CreateOtpResult, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.OtpMaxAttemptsReached(result.Outcome)),
            _ => Result<CreateOtpResult, VerificationFlowFailure>.Err(
                VerificationFlowFailure.OtpGenerationFailed(result.Outcome))
        };
    }

    private async Task<Result<Guid, VerificationFlowFailure>> EnsurePhoneNumberAsync(IDbConnection conn,
        EnsurePhoneNumberActorEvent cmd)
    {
        EnsurePhoneNumberResult? result = await conn.QuerySingleOrDefaultAsync<EnsurePhoneNumberResult>(
            "dbo.EnsurePhoneNumber",
            new
            {
                PhoneNumberString = cmd.PhoneNumber, Region = cmd.RegionCode,
                AppDeviceId = cmd.AppDeviceIdentifier
            },
            commandType: CommandType.StoredProcedure);

        if (result is null)
            return Result<Guid, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess("Unknown error: EnsurePhoneNumber returned no result."));

        return !result.Success
            ? Result<Guid, VerificationFlowFailure>.Err(VerificationFlowFailure.Validation(result.Outcome))
            : Result<Guid, VerificationFlowFailure>.Ok(result.UniqueId);
    }

    private static Result<VerificationFlowQueryRecord, VerificationFlowFailure> MapToVerificationFlowRecord(
        InitiateVerificationFlowResult result)
    {
        Option<OtpQueryRecord> otpActive = result.Otp_UniqueIdentifier.HasValue
            ? Option<OtpQueryRecord>.Some(new OtpQueryRecord
            {
                UniqueIdentifier = result.Otp_UniqueIdentifier.Value,
                FlowUniqueId = result.Otp_FlowUniqueId!.Value,
                PhoneNumberIdentifier = result.PhoneNumberIdentifier,
                OtpHash = result.Otp_OtpHash!,
                OtpSalt = result.Otp_OtpSalt!,
                ExpiresAt = result.Otp_ExpiresAt!.Value,
                Status = Enum.Parse<VerificationFlowStatus>(result.Otp_Status!, true),
                IsActive = result.Otp_IsActive!.Value
            })
            : Option<OtpQueryRecord>.None;

        VerificationFlowQueryRecord flowRecord = new()
        {
            UniqueIdentifier = result.UniqueIdentifier,
            PhoneNumberIdentifier = result.PhoneNumberIdentifier,
            AppDeviceIdentifier = result.AppDeviceIdentifier,
            ConnectId = (uint?)result.ConnectId,
            ExpiresAt = result.ExpiresAt,
            Status = Enum.Parse<VerificationFlowStatus>(result.Status, true),
            Purpose = Enum.Parse<VerificationPurpose>(result.Purpose, true),
            OtpCount = result.OtpCount,
            OtpActive = otpActive.HasValue ? otpActive.Value : null
        };

        return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Ok(flowRecord);
    }

    protected override VerificationFlowFailure MapDbException(DbException ex)
    {
        if (ex is SqlException sqlEx)
            return sqlEx.Number switch
            {
                2627 or 2601 => VerificationFlowFailure.ConcurrencyConflict(sqlEx.Message),
                547 => VerificationFlowFailure.Validation($"Foreign key violation: {sqlEx.Message}"),
                _ => VerificationFlowFailure.PersistorAccess(sqlEx)
            };

        return VerificationFlowFailure.PersistorAccess(ex);
    }

    protected override VerificationFlowFailure CreateTimeoutFailure(TimeoutException ex)
    {
        return VerificationFlowFailure.PersistorAccess("Database operation timed out.", ex);
    }

    protected override VerificationFlowFailure CreateGenericFailure(Exception ex)
    {
        return VerificationFlowFailure.Generic(VerificationFlowMessageKeys.Generic, ex);
    }
}