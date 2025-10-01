using System.Data;
using System.Data.Common;
using Akka.Actor;
using Dapper;
using Ecliptix.Domain.DbConnectionFactory;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.QueryResults;
using Ecliptix.Utilities;
using Ecliptix.Protobuf.Membership;
using Microsoft.Data.SqlClient;
using Serilog;

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
        Receive<VerifyPhoneForSecretKeyRecoveryActorEvent>(actorEvent =>
            ExecuteWithConnection(conn => VerifyPhoneForSecretKeyRecoveryAsync(conn, actorEvent),
                    "VerifyPhoneForSecretKeyRecovery")
                .PipeTo(Sender));
        Receive<GetPhoneNumberActorEvent>(actorEvent =>
            ExecuteWithConnection(conn => GetPhoneNumberAsync(conn, actorEvent), "GetPhoneNumber").PipeTo(Sender));
        Receive<CreateOtpActorEvent>(actorEvent =>
            ExecuteWithConnection(conn => CreateOtpAsync(conn, actorEvent), "CreateOtp").PipeTo(Sender));
        Receive<UpdateOtpStatusActorEvent>(actorEvent =>
            ExecuteWithConnection(conn => UpdateOtpStatusAsync(conn, actorEvent), "UpdateOtpStatus").PipeTo(Sender));
        Receive<ExpireAssociatedOtpActorEvent>(actorEvent => 
            ExecuteWithConnection(conn => ExpireAssociatedOtpAsync(conn, actorEvent), "ExpireAssociatedOtp")
                .PipeTo(Sender));
    }

    private static async Task<Result<VerificationFlowQueryRecord, VerificationFlowFailure>> InitiateFlowAsync(
        IDbConnection conn, InitiateFlowAndReturnStateActorEvent cmd)
    {
        DynamicParameters parameters = new();
        parameters.Add("@AppDeviceId", cmd.AppDeviceId);
        parameters.Add("@PhoneUniqueId", cmd.PhoneNumberId);
        parameters.Add("@Purpose", cmd.Purpose.ToString().ToLowerInvariant());
        parameters.Add("@ConnectionId", (long?)cmd.ConnectId);

        InitiateVerificationFlowResult? result = await conn.QuerySingleOrDefaultAsync<InitiateVerificationFlowResult>(
            "dbo.SP_InitiateVerificationFlow",
            parameters,
            commandType: CommandType.StoredProcedure);

        if (result is null)
            return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(VerificationFlowFailure.NotFound());

        return result.Outcome switch
        {
            "phone_not_found" => Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.NotFound(result.Outcome)),
            "global_rate_limit_exceeded" => Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.RateLimitExceeded(VerificationFlowMessageKeys.GlobalRateLimitExceeded)),
            _ => MapToVerificationFlowRecord(result)
        };
    }

    private static async Task<Result<string, VerificationFlowFailure>> RequestResendOtpAsync(IDbConnection conn,
        RequestResendOtpActorEvent cmd)
    {
        DynamicParameters parameters = new();
        parameters.Add("@FlowUniqueId", cmd.FlowUniqueId);

        RequestResendOtpResult? result = await conn.QuerySingleOrDefaultAsync<RequestResendOtpResult>(
            "dbo.SP_RequestResendOtpCode",
            parameters,
            commandType: CommandType.StoredProcedure
        );

        if (result != null) return Result<string, VerificationFlowFailure>.Ok(result.Outcome);
        Log.Error("RequestResendOtp stored procedure returned null for FlowUniqueId {FlowUniqueId}", cmd.FlowUniqueId);
        return Result<string, VerificationFlowFailure>.Err(
            VerificationFlowFailure.PersistorAccess("Failed to request OTP resend - no result returned"));
    }

    private async Task<Result<Unit, VerificationFlowFailure>> UpdateOtpStatusAsync(IDbConnection conn,
        UpdateOtpStatusActorEvent cmd)
    {
        DynamicParameters parameters = new();
        parameters.Add("@OtpUniqueId", cmd.OtpIdentified);
        parameters.Add("@NewStatus", cmd.Status.ToString().ToLowerInvariant());

        UpdateOtpStatusResult? result = await conn.QuerySingleOrDefaultAsync<UpdateOtpStatusResult>(
            "dbo.SP_UpdateOtpStatus",
            parameters,
            commandType: CommandType.StoredProcedure);

        if (result != null)
            return result.Success
                ? Result<Unit, VerificationFlowFailure>.Ok(Unit.Value)
                : Result<Unit, VerificationFlowFailure>.Err(VerificationFlowFailure.PersistorAccess(result.Message));
        Log.Error("UpdateOtpStatus stored procedure returned null for OtpUniqueId {OtpUniqueId}", cmd.OtpIdentified);
        return Result<Unit, VerificationFlowFailure>.Err(
            VerificationFlowFailure.PersistorAccess("Failed to update OTP status - no result returned"));

    }

    private async Task<Result<PhoneNumberQueryRecord, VerificationFlowFailure>> GetPhoneNumberAsync(IDbConnection conn,
        GetPhoneNumberActorEvent cmd)
    {
        DynamicParameters parameters = new();
        parameters.Add("@PhoneUniqueId", cmd.PhoneNumberIdentifier);

        PhoneNumberQueryRecord? result = await conn.QuerySingleOrDefaultAsync<PhoneNumberQueryRecord>(
            "dbo.SP_GetMobileNumber",
            parameters,
            commandType: CommandType.StoredProcedure);

        if (result == null)
        {
            Log.Warning("Phone number not found for PhoneUniqueId {PhoneUniqueId}", cmd.PhoneNumberIdentifier);
            return Result<PhoneNumberQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.NotFound(VerificationFlowMessageKeys.PhoneNotFound));
        }

        return Result<PhoneNumberQueryRecord, VerificationFlowFailure>.Ok(result);
    }

    private async Task<Result<int, VerificationFlowFailure>> UpdateVerificationFlowStatusAsync(IDbConnection conn,
        UpdateVerificationFlowStatusActorEvent cmd)
    {
        DynamicParameters parameters = new DynamicParameters();
        parameters.Add("@FlowUniqueId", cmd.FlowIdentifier);
        parameters.Add("@NewStatus", cmd.Status.ToString().ToLowerInvariant());
        parameters.Add("@rowsAffected", dbType: DbType.Int32, direction: ParameterDirection.ReturnValue);

        await conn.ExecuteAsync("dbo.SP_UpdateVerificationFlowStatus", parameters,
            commandType: CommandType.StoredProcedure);

        return Result<int, VerificationFlowFailure>.Ok(parameters.Get<int>("@rowsAffected"));
    }

    private static async Task<Result<CreateOtpResult, VerificationFlowFailure>> CreateOtpAsync(IDbConnection conn,
        CreateOtpActorEvent cmd)
    {
        DynamicParameters parameters = new();
        parameters.Add("@FlowUniqueId", cmd.OtpRecord.FlowUniqueId);
        parameters.Add("@OtpHash", cmd.OtpRecord.OtpHash);
        parameters.Add("@OtpSalt", cmd.OtpRecord.OtpSalt);
        parameters.Add("@ExpiresAt", cmd.OtpRecord.ExpiresAt);
        parameters.Add("@Status", cmd.OtpRecord.Status.ToString().ToLowerInvariant());

        CreateOtpResult? result = await conn.QuerySingleOrDefaultAsync<CreateOtpResult>(
            "dbo.SP_InsertOtpRecord",
            parameters,
            commandType: CommandType.StoredProcedure);

        if (result != null)
            return result.Outcome switch
            {
                "created" => Result<CreateOtpResult, VerificationFlowFailure>.Ok(result),
                "flow_not_found_or_invalid" =>
                    Result<CreateOtpResult, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.NotFound(result.Outcome)),
                "max_otp_attempts_reached" =>
                    Result<CreateOtpResult, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.OtpMaxAttemptsReached(result.Outcome)),
                _ => Result<CreateOtpResult, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.OtpGenerationFailed(result.Outcome))
            };
        Log.Error("InsertOtpRecord stored procedure returned null for FlowUniqueId {FlowUniqueId}", cmd.OtpRecord.FlowUniqueId);
        return Result<CreateOtpResult, VerificationFlowFailure>.Err(
            VerificationFlowFailure.OtpGenerationFailed("Failed to create OTP record - no result returned"));

    }

    private async Task<Result<Guid, VerificationFlowFailure>> EnsurePhoneNumberAsync(IDbConnection conn,
        EnsurePhoneNumberActorEvent cmd)
    {
        DynamicParameters parameters = new();
        parameters.Add("@PhoneNumberString", cmd.PhoneNumber);
        parameters.Add("@Region", cmd.RegionCode);
        parameters.Add("@AppDeviceId", cmd.AppDeviceIdentifier);

        EnsurePhoneNumberResult? result = await conn.QuerySingleOrDefaultAsync<EnsurePhoneNumberResult>(
            "dbo.SP_EnsureMobileNumber",
            parameters,
            commandType: CommandType.StoredProcedure);

        if (result is not null)
            return !result.Success
                ? Result<Guid, VerificationFlowFailure>.Err(VerificationFlowFailure.Validation(result.Outcome))
                : Result<Guid, VerificationFlowFailure>.Ok(result.UniqueId);
        Log.Error("EnsurePhoneNumber stored procedure returned null for PhoneNumber {PhoneNumber}, AppDeviceId {AppDeviceId}",
            cmd.PhoneNumber, cmd.AppDeviceIdentifier);
        return Result<Guid, VerificationFlowFailure>.Err(
            VerificationFlowFailure.PersistorAccess("Failed to ensure phone number - no result returned"));

    }

    private static async Task<Result<Guid, VerificationFlowFailure>> VerifyPhoneForSecretKeyRecoveryAsync(IDbConnection conn,
        VerifyPhoneForSecretKeyRecoveryActorEvent cmd)
    {
        DynamicParameters parameters = new();
        parameters.Add("@PhoneNumberString", cmd.PhoneNumber);
        parameters.Add("@Region", cmd.RegionCode);

        VerifyPhoneForSecretKeyRecoveryResult? result =
            await conn.QuerySingleOrDefaultAsync<VerifyPhoneForSecretKeyRecoveryResult>(
                "dbo.SP_VerifyMobileForSecretKeyRecovery",
                parameters,
                commandType: CommandType.StoredProcedure);

        if (result is null)
        {
            Log.Error("VerifyPhoneForSecretKeyRecovery stored procedure returned null for PhoneNumber {PhoneNumber}",
                cmd.PhoneNumber);
            return Result<Guid, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess("Failed to verify phone for secret key recovery - no result returned"));
        }

        return result.Success
            ? Result<Guid, VerificationFlowFailure>.Ok(result.PhoneNumberUniqueId)
            : Result<Guid, VerificationFlowFailure>.Err(VerificationFlowFailure.Validation(result.Outcome));
    }

    private async Task<Result<Unit, VerificationFlowFailure>> ExpireAssociatedOtpAsync(IDbConnection conn, 
        ExpireAssociatedOtpActorEvent cmd)
    {
        DynamicParameters parameters = new();
        parameters.Add("@FlowUniqueId", cmd.FlowUniqueId);

        await conn.ExecuteAsync(
            "dbo.SP_ExpireAssociatedOtp",
            parameters,
            commandType: CommandType.StoredProcedure);

        return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
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
        Log.Error(ex, "Database exception in {ActorType}: {ExceptionType} - {Message}", 
            GetType().Name, ex.GetType().Name, ex.Message);

        if (ex is SqlException sqlEx)
        {
            return sqlEx.Number switch
            {
                2627 or 2601 => VerificationFlowFailure.ConcurrencyConflict($"Unique constraint violation: {sqlEx.Message}"),
                547 => VerificationFlowFailure.Validation($"Foreign key constraint violation: {sqlEx.Message}"),
                1205 => VerificationFlowFailure.ConcurrencyConflict($"Deadlock detected: {sqlEx.Message}"),
                -2 => VerificationFlowFailure.PersistorAccess("Command timeout occurred", sqlEx),
                2 => VerificationFlowFailure.PersistorAccess("Network error occurred", sqlEx),
                18456 => VerificationFlowFailure.PersistorAccess("Authentication failed", sqlEx),
                _ => VerificationFlowFailure.PersistorAccess($"Database error (Code: {sqlEx.Number}): {sqlEx.Message}", sqlEx)
            };
        }

        return VerificationFlowFailure.PersistorAccess("Database operation failed", ex);
    }

    protected override VerificationFlowFailure CreateTimeoutFailure(TimeoutException ex)
    {
        Log.Error(ex, "Timeout exception in {ActorType}: Operation timed out", GetType().Name);
        return VerificationFlowFailure.PersistorAccess("Database operation timed out", ex);
    }

    protected override VerificationFlowFailure CreateGenericFailure(Exception ex)
    {
        Log.Error(ex, "Generic exception in {ActorType}: {ExceptionType} - {Message}", 
            GetType().Name, ex.GetType().Name, ex.Message);
        return VerificationFlowFailure.Generic($"Unexpected error in verification flow persistor: {ex.Message}", ex);
    }

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return PersistorSupervisorStrategy.CreateStrategy();
    }
}