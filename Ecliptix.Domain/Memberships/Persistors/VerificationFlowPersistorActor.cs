using System.Data;
using System.Data.Common;
using Akka.Actor;
using Dapper;
using Ecliptix.Domain.DbConnectionFactory;
using Ecliptix.Domain.Memberships.Events;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.Utilities;
using Ecliptix.Domain.Persistors;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Logging;

namespace Ecliptix.Domain.Memberships.Persistors;

internal class EnsurePhoneNumberResult
{
    public Guid UniqueId { get; set; }
    public string Outcome { get; set; } = string.Empty;
    public bool Success { get; set; }
}

internal class CreateVerificationFlowResult
{
    public Guid? FlowUniqueId { get; set; }
    public string Outcome { get; set; } = string.Empty;
}

internal class VerificationFlowQueryResult
{
    public Guid FlowUniqueId { get; set; }
    public Guid PhoneNumberUniqueId { get; set; }
    public Guid AppDeviceId { get; set; }
    public long? ConnectionId { get; set; }
    public DateTime ExpiresAt { get; set; }
    public string Status { get; set; } = string.Empty;
    public string Purpose { get; set; } = string.Empty;
    public short OtpCount { get; set; }
    public Guid? OtpUniqueId { get; set; }
    public string? OtpHash { get; set; }
    public string? OtpSalt { get; set; }
    public DateTime? OtpExpiresAt { get; set; }
    public string? OtpStatus { get; set; }
}

internal class CreateOtpResult
{
    public Guid? OtpUniqueId { get; set; }
    public string Outcome { get; set; } = string.Empty;
}

internal class UpdateOtpStatusResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
}

public class VerificationFlowPersistorActor : PersistorBase<VerificationFlowFailure>
{
    public VerificationFlowPersistorActor(
        IDbConnectionFactory connectionFactory,
        ILogger<VerificationFlowPersistorActor> logger)
        : base(connectionFactory, logger)
    {
        Become(Ready);
    }

    public static Props Build(IDbConnectionFactory connectionFactory,
        ILogger<VerificationFlowPersistorActor> logger) =>
        Props.Create(() => new VerificationFlowPersistorActor(connectionFactory, logger));

    private void Ready()
    {
        Receive<CreateVerificationFlowActorEvent>(cmd =>
            Execute(conn => CreateVerificationFlowAsync(conn, cmd), "CreateVerificationFlow"));
        Receive<GetVerificationFlowActorEvent>(cmd =>
            Execute(conn => GetVerificationFlowAsync(conn, cmd), "GetVerificationFlow"));
        Receive<UpdateVerificationFlowStatusActorEvent>(cmd =>
            Execute(conn => UpdateVerificationFlowStatusAsync(conn, cmd), "UpdateVerificationFlowStatus"));
        Receive<EnsurePhoneNumberActorEvent>(cmd =>
            Execute(conn => EnsurePhoneNumberAsync(conn, cmd), "EnsurePhoneNumber"));
        Receive<GetPhoneNumberActorEvent>(cmd => Execute(conn => GetPhoneNumberAsync(conn, cmd), "GetPhoneNumber"));
        Receive<CreateOtpActorEvent>(cmd => Execute(conn => CreateOtpAsync(conn, cmd), "CreateOtp"));
        Receive<UpdateOtpStatusActorEvent>(cmd => Execute(conn => UpdateOtpStatusAsync(conn, cmd), "UpdateOtpStatus"));
    }

    private void Execute<T>(Func<IDbConnection, Task<T>> operation, string operationName)
    {
        ExecuteWithConnection(async conn =>
        {
            T result = await operation(conn);
            return Result<T, VerificationFlowFailure>.Ok(result);
        }, operationName).PipeTo(Self, sender: Sender);
    }

    private async Task<Result<Unit, VerificationFlowFailure>> UpdateOtpStatusAsync(IDbConnection conn,
        UpdateOtpStatusActorEvent cmd)
    {
        DynamicParameters parameters = new DynamicParameters();
        parameters.Add("@OtpUniqueId", cmd.OtpIdentified);
        parameters.Add("@NewStatus", cmd.Status.ToString().ToLowerInvariant());
        parameters.Add("@Success", dbType: DbType.Boolean, direction: ParameterDirection.Output);
        parameters.Add("@Message", dbType: DbType.String, size: 255, direction: ParameterDirection.Output);

        await conn.ExecuteAsync("dbo.UpdateOtpStatus", parameters, commandType: CommandType.StoredProcedure);

        bool success = parameters.Get<bool>("@Success");
        string message = parameters.Get<string>("@Message");

        return success
            ? Result<Unit, VerificationFlowFailure>.Ok(Unit.Value)
            : Result<Unit, VerificationFlowFailure>.Err(VerificationFlowFailure.PersistorAccess(message));
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

    private async Task<Result<Guid, VerificationFlowFailure>> CreateVerificationFlowAsync(IDbConnection conn,
        CreateVerificationFlowActorEvent cmd)
    {
        DynamicParameters parameters = new();
        parameters.Add("@AppDeviceId", cmd.AppDeviceIdentifier);
        parameters.Add("@PhoneUniqueId", cmd.PhoneNumberIdentifier);
        parameters.Add("@Purpose", cmd.Purpose.ToString().ToLowerInvariant());
        parameters.Add("@ExpiresAt", cmd.ExpiresAt);
        parameters.Add("@ConnectionId", (long)cmd.ConnectId);
        parameters.Add("@FlowUniqueId", dbType: DbType.Guid, direction: ParameterDirection.Output);
        parameters.Add("@Outcome", dbType: DbType.String, size: 50, direction: ParameterDirection.Output);

        await conn.ExecuteAsync("dbo.CreateVerificationFlow", parameters, commandType: CommandType.StoredProcedure);

        string outcome = parameters.Get<string>("@Outcome");
        Guid? flowUniqueId = parameters.Get<Guid?>("@FlowUniqueId");

        return outcome switch
        {
            VerificationFlowMessageKeys.Created or
                VerificationFlowMessageKeys.ExistingSessionReusedAndUpdated or
                VerificationFlowMessageKeys.ConflictResolvedToExisting
                when flowUniqueId.HasValue => Result<Guid, VerificationFlowFailure>.Ok(flowUniqueId.Value),

            VerificationFlowMessageKeys.PhoneNotFound => Result<Guid, VerificationFlowFailure>.Err(
                VerificationFlowFailure.NotFound(outcome)),
            VerificationFlowMessageKeys.ConflictUnresolved => Result<Guid, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Conflict(outcome)),
            _ => Result<Guid, VerificationFlowFailure>.Err(VerificationFlowFailure.PersistorAccess(outcome))
        };
    }

    private async Task<Result<Option<VerificationFlowQueryRecord>, VerificationFlowFailure>> GetVerificationFlowAsync(
        IDbConnection conn, GetVerificationFlowActorEvent cmd)
    {
        VerificationFlowQueryResult? result = await conn.QuerySingleOrDefaultAsync<VerificationFlowQueryResult>(
            "dbo.GetVerificationFlow",
            new
            {
                AppDeviceId = cmd.DeviceId, PhoneUniqueId = cmd.PhoneNumberIdentifier,
                Purpose = cmd.Purpose.ToString().ToLowerInvariant()
            },
            commandType: CommandType.StoredProcedure);

        if (result == null)
        {
            return Result<Option<VerificationFlowQueryRecord>, VerificationFlowFailure>.Ok(
                Option<VerificationFlowQueryRecord>.None);
        }

        Option<OtpQueryRecord> otpActive = result.OtpUniqueId.HasValue
            ? Option<OtpQueryRecord>.Some(new OtpQueryRecord
            {
                UniqueIdentifier = result.OtpUniqueId.Value,
                FlowUniqueId = result.FlowUniqueId,
                OtpHash = result.OtpHash!,
                OtpSalt = result.OtpSalt!,
                ExpiresAt = result.OtpExpiresAt!.Value,
                Status = Enum.Parse<VerificationFlowStatus>(result.OtpStatus!,
                    true),
                IsActive = true,
                PhoneNumberIdentifier = default
            })
            : Option<OtpQueryRecord>.None;

        VerificationFlowQueryRecord flowRecord =
            new(result.FlowUniqueId, result.PhoneNumberUniqueId, result.AppDeviceId)
            {
                ConnectId = (uint?)result.ConnectionId,
                ExpiresAt = result.ExpiresAt,
                Status = Enum.Parse<VerificationFlowStatus>(result.Status, true),
                Purpose = Enum.Parse<VerificationPurpose>(result.Purpose, true),
                OtpCount = result.OtpCount,
                OtpActive = otpActive
            };

        return Result<Option<VerificationFlowQueryRecord>, VerificationFlowFailure>.Ok(
            Option<VerificationFlowQueryRecord>.Some(flowRecord));
    }

    private async Task<Result<Unit, VerificationFlowFailure>> UpdateVerificationFlowStatusAsync(IDbConnection conn,
        UpdateVerificationFlowStatusActorEvent cmd)
    {
        await conn.ExecuteAsync(
            "dbo.UpdateVerificationFlowStatus",
            new { FlowUniqueId = cmd.FlowIdentifier, NewStatus = cmd.Status.ToString().ToLowerInvariant() },
            commandType: CommandType.StoredProcedure);

        return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
    }

    private async Task<Result<CreateOtpRecordResult, VerificationFlowFailure>> CreateOtpAsync(IDbConnection conn,
        CreateOtpActorEvent cmd)
    {
        var parameters = new DynamicParameters();
        parameters.Add("@FlowUniqueId", cmd.OtpRecord.FlowUniqueId);
        parameters.Add("@OtpHash", cmd.OtpRecord.OtpHash);
        parameters.Add("@OtpSalt", cmd.OtpRecord.OtpSalt);
        parameters.Add("@ExpiresAt", cmd.OtpRecord.ExpiresAt);
        parameters.Add("@Status", cmd.OtpRecord.Status.ToString().ToLowerInvariant());
        parameters.Add("@OtpUniqueId", dbType: DbType.Guid, direction: ParameterDirection.Output);
        parameters.Add("@Outcome", dbType: DbType.String, size: 50, direction: ParameterDirection.Output);

        await conn.ExecuteAsync("dbo.InsertOtpRecord", parameters, commandType: CommandType.StoredProcedure);

        string outcome = parameters.Get<string>("@Outcome");
        Guid? otpUniqueId = parameters.Get<Guid?>("@OtpUniqueId");

        return outcome switch
        {
            VerificationFlowMessageKeys.Created when otpUniqueId.HasValue => Result<CreateOtpRecordResult,
                    VerificationFlowFailure>
                .Ok(new CreateOtpRecordResult(otpUniqueId.Value)),
            VerificationFlowMessageKeys.VerificationFlowNotFound => Result<CreateOtpRecordResult,
                    VerificationFlowFailure>
                .Err(VerificationFlowFailure.NotFound(outcome)),
            VerificationFlowMessageKeys.OtpMaxAttemptsReached => Result<CreateOtpRecordResult, VerificationFlowFailure>
                .Err(
                    VerificationFlowFailure.OtpMaxAttemptsReached(outcome)),
            _ => Result<CreateOtpRecordResult, VerificationFlowFailure>.Err(
                VerificationFlowFailure.OtpGenerationFailed(outcome))
        };
    }

    private async Task<Result<Guid, VerificationFlowFailure>> EnsurePhoneNumberAsync(IDbConnection conn,
        EnsurePhoneNumberActorEvent cmd)
    {
        DynamicParameters parameters = new();
        parameters.Add("@PhoneNumberString", cmd.PhoneNumber);
        parameters.Add("@Region", cmd.RegionCode);
        parameters.Add("@AppDeviceId", cmd.AppDeviceIdentifier);

        EnsurePhoneNumberResult? result = await conn.QuerySingleOrDefaultAsync<EnsurePhoneNumberResult>(
            "dbo.EnsurePhoneNumber",
            parameters,
            commandType: CommandType.StoredProcedure);

        if (result is null || (!result.Success && result.UniqueId == Guid.Empty))
        {
            return Result<Guid, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess(result?.Outcome ?? "Unknown error"));
        }

        if (!result.Success)
        {
            return Result<Guid, VerificationFlowFailure>.Err(VerificationFlowFailure.Validation(result.Outcome));
        }

        return Result<Guid, VerificationFlowFailure>.Ok(result.UniqueId);
    }

    protected override IDbDataParameter CreateParameter(string name, object value) => new SqlParameter(name, value);

    protected override VerificationFlowFailure MapDbException(DbException ex)
    {
        if (ex is SqlException sqlEx)
        {
            return sqlEx.Number switch
            {
                2627 or 2601 => VerificationFlowFailure.ConcurrencyConflict(sqlEx.Message),
                547 => VerificationFlowFailure.Validation($"Foreign key violation: {sqlEx.Message}"),
                _ => VerificationFlowFailure.PersistorAccess(sqlEx)
            };
        }

        return VerificationFlowFailure.PersistorAccess(ex);
    }

    protected override VerificationFlowFailure CreateTimeoutFailure(TimeoutException ex)
    {
        throw new NotImplementedException();
    }

    protected override VerificationFlowFailure CreateGenericFailure(Exception ex)
    {
        throw new NotImplementedException();
    }
}

