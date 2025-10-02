using System.Data;
using System.Data.Common;
using Akka.Actor;
using Dapper;
using Ecliptix.Domain.DbConnectionFactory;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.QueryResults;
using Ecliptix.Domain.Memberships.WorkerActors;
using Ecliptix.Utilities;
using Ecliptix.Protobuf.Membership;
using Microsoft.Data.SqlClient;
using Serilog;

namespace Ecliptix.Domain.Memberships.Persistors;

public class MembershipPersistorActor : PersistorBase<VerificationFlowFailure>
{
    private static readonly Dictionary<string, Membership.Types.ActivityStatus> MembershipStatusMap = new()
    {
        ["active"] = Membership.Types.ActivityStatus.Active,
        ["inactive"] = Membership.Types.ActivityStatus.Inactive
    };

    public MembershipPersistorActor(
        IDbConnectionFactory connectionFactory)
        : base(connectionFactory)
    {
        Become(Ready);
    }

    public static Props Build(IDbConnectionFactory connectionFactory)
    {
        return Props.Create(() => new MembershipPersistorActor(connectionFactory));
    }

    private void Ready()
    {
        Receive<UpdateMembershipSecureKeyEvent>(cmd =>
            ExecuteWithConnection(conn => UpdateMembershipSecureKeyAsync(conn, cmd), "UpdateMembershipSecureKey")
                .PipeTo(Sender));

        Receive<CreateMembershipActorEvent>(cmd =>
            ExecuteWithConnection(conn => CreateMembershipAsync(conn, cmd), "CreateMembership")
                .PipeTo(Sender));

        Receive<SignInMembershipActorEvent>(cmd =>
            ExecuteWithConnection(conn => SignInMembershipAsync(conn, cmd), "LoginMembership")
                .PipeTo(Sender));
    }

    private async Task<Result<MembershipQueryRecord, VerificationFlowFailure>> SignInMembershipAsync(
        IDbConnection connection, SignInMembershipActorEvent cmd)
    {
        DynamicParameters parameters = new();
        parameters.Add("@MobileNumber", cmd.MobileNumber, DbType.String, ParameterDirection.Input);
        parameters.Add("@MembershipUniqueId", dbType: DbType.Guid, direction: ParameterDirection.Output);
        parameters.Add("@Status", dbType: DbType.String, direction: ParameterDirection.Output, size: 20);
        parameters.Add("@Outcome", dbType: DbType.String, direction: ParameterDirection.Output, size: 500);
        parameters.Add("@SecureKey", dbType: DbType.Binary, direction: ParameterDirection.Output,size:-1);
        parameters.Add("@MaskingKey", dbType: DbType.Binary, direction: ParameterDirection.Output,size:32);
        parameters.Add("@ErrorMessage", dbType: DbType.String, direction: ParameterDirection.Output, size: 500);

        await connection.ExecuteAsync(
            "dbo.SP_LoginMembership",
            parameters,
            commandType: CommandType.StoredProcedure
        );

        string? outcome = parameters.Get<string>("@Outcome");
        Guid? membershipUniqueId = parameters.Get<Guid?>("@MembershipUniqueId");
        string? status = parameters.Get<string>("@Status");
        byte[]? secureKey = parameters.Get<byte[]>("@SecureKey");
        byte[]? maskingKey = parameters.Get<byte[]>("@MaskingKey");
        string? errorMessage = parameters.Get<string>("@ErrorMessage");

        if (string.IsNullOrEmpty(outcome))
        {
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess(
                    "Login membership failed - stored procedure returned null outcome"));
        }

        if (int.TryParse(outcome, out int _))
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.RateLimitExceeded(outcome));

        return outcome switch
        {
            "success" when membershipUniqueId.HasValue && !string.IsNullOrEmpty(status) =>
                MapActivityStatus(status).Match(
                    activityStatus => Result<MembershipQueryRecord, VerificationFlowFailure>.Ok(
                        new MembershipQueryRecord
                        {
                            UniqueIdentifier = membershipUniqueId.Value,
                            ActivityStatus = activityStatus,
                            CreationStatus = Membership.Types.CreationStatus.OtpVerified,
                            SecureKey = secureKey ?? [],
                            MaskingKey = maskingKey ?? []
                        }),
                    () => Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.ActivityStatusInvalid))
                ),

            string error when IsKnownLoginError(error) =>
                Result<MembershipQueryRecord, VerificationFlowFailure>.Err(VerificationFlowFailure.Validation(error)),

            string outcomeValue =>
                Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.PersistorAccess(!string.IsNullOrEmpty(errorMessage)
                        ? errorMessage
                        : outcomeValue))
        };
    }

    private async Task<Result<MembershipQueryRecord, VerificationFlowFailure>> UpdateMembershipSecureKeyAsync(
        IDbConnection connection, UpdateMembershipSecureKeyEvent cmd)
    {
        DynamicParameters parameters = new();
        parameters.Add("@MembershipUniqueId", cmd.MembershipIdentifier);
        parameters.Add("@SecureKey", cmd.SecureKey);
        parameters.Add("@MaskingKey", cmd.MaskingKey);

        UpdateSecureKeyResult? result = await connection.QuerySingleOrDefaultAsync<UpdateSecureKeyResult>(
            "dbo.SP_UpdateMembershipSecureKey",
            parameters,
            commandType: CommandType.StoredProcedure
        );

        if (result is null)
        {
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess(
                    "Update membership secure key failed - stored procedure returned null result"));
        }

        if (!result.Success)
        {
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Validation($"Secure key update failed: {result.Message}"));
        }

        if (!result.MembershipUniqueId.HasValue || string.IsNullOrEmpty(result.Status) ||
            string.IsNullOrEmpty(result.CreationStatus))
        {
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess("Secure key update succeeded but returned incomplete data"));
        }

        return MapActivityStatus(result.Status).Match(
            status => Result<MembershipQueryRecord, VerificationFlowFailure>.Ok(
                new MembershipQueryRecord
                {
                    UniqueIdentifier = result.MembershipUniqueId.Value,
                    ActivityStatus = status,
                    CreationStatus = MembershipCreationStatusHelper.GetCreationStatusEnum(result.CreationStatus),
                    MaskingKey = result.MaskingKey
                }),
            () => Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.ActivityStatusInvalid))
        );
    }

    private static async Task<Result<MembershipQueryRecord, VerificationFlowFailure>> CreateMembershipAsync(
        IDbConnection connection, CreateMembershipActorEvent cmd)
    {
        DynamicParameters parameters = new();
        parameters.Add("@FlowUniqueId", cmd.VerificationFlowIdentifier);
        parameters.Add("@ConnectionId", (long)cmd.ConnectId);
        parameters.Add("@OtpUniqueId", cmd.OtpIdentifier);
        parameters.Add("@CreationStatus", MembershipCreationStatusHelper.GetCreationStatusString(cmd.CreationStatus));

        CreateMembershipResult? result = await connection.QuerySingleOrDefaultAsync<CreateMembershipResult>(
            "dbo.SP_CreateMembership",
            parameters,
            commandType: CommandType.StoredProcedure);

        if (result is null)
        {
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess(
                    "Create membership failed - stored procedure returned null result"));
        }

        if (int.TryParse(result.Outcome, out int rateLimitSeconds))
        {
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.RateLimitExceeded(rateLimitSeconds.ToString()));
        }

        return result.Outcome switch
        {
            VerificationFlowMessageKeys.Created
                or VerificationFlowMessageKeys.MembershipAlreadyExists when result.MembershipUniqueId.HasValue &&
                                                                            !string.IsNullOrEmpty(result.Status) &&
                                                                            !string.IsNullOrEmpty(result.CreationStatus)
                =>
                MapActivityStatus(result.Status).Match(
                    status => Result<MembershipQueryRecord, VerificationFlowFailure>.Ok(
                        new MembershipQueryRecord
                        {
                            UniqueIdentifier = result.MembershipUniqueId.Value,
                            ActivityStatus = status,
                            CreationStatus = MembershipCreationStatusHelper.GetCreationStatusEnum(result.CreationStatus)
                        }),
                    () => Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.ActivityStatusInvalid))
                ),

            string error when IsKnownCreationError(error) => CreateValidationError(cmd, error),

            string outcome => CreatePersistorAccessError(cmd, outcome)
        };
    }

    private static Result<MembershipQueryRecord, VerificationFlowFailure> CreateValidationError(
        CreateMembershipActorEvent cmd, string error)
    {
        return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(VerificationFlowFailure.Validation(error));
    }

    private static Result<MembershipQueryRecord, VerificationFlowFailure> CreatePersistorAccessError(
        CreateMembershipActorEvent cmd, string outcome)
    {
        return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
            VerificationFlowFailure.PersistorAccess($"Membership creation failed: {outcome}"));
    }

    private static bool IsKnownLoginError(string outcome)
    {
        return outcome is VerificationFlowMessageKeys.InvalidSecureKey or
            VerificationFlowMessageKeys.InactiveMembership or
            VerificationFlowMessageKeys.MobileNumberCannotBeEmpty or
            VerificationFlowMessageKeys.SecureKeyCannotBeEmpty or
            VerificationFlowMessageKeys.SecureKeyNotSet or
            VerificationFlowMessageKeys.MobileNotFound or
            VerificationFlowMessageKeys.MembershipNotFound;
    }

    private static bool IsKnownCreationError(string outcome)
    {
        return outcome is VerificationFlowMessageKeys.CreateMembershipVerificationFlowNotFound;
    }

    private static Option<Membership.Types.ActivityStatus> MapActivityStatus(string? statusStr)
    {
        if (string.IsNullOrEmpty(statusStr) ||
            !MembershipStatusMap.TryGetValue(statusStr, out Membership.Types.ActivityStatus status))
            return Option<Membership.Types.ActivityStatus>.None;

        return Option<Membership.Types.ActivityStatus>.Some(status);
    }

    protected override VerificationFlowFailure MapDbException(DbException ex)
    {
        if (ex is SqlException sqlEx)
        {
            return sqlEx.Number switch
            {
                2627 or 2601 => VerificationFlowFailure.ConcurrencyConflict(
                    $"Unique constraint violation: {sqlEx.Message}"),
                547 => VerificationFlowFailure.Validation($"Foreign key constraint violation: {sqlEx.Message}"),
                1205 => VerificationFlowFailure.ConcurrencyConflict($"Deadlock detected: {sqlEx.Message}"),
                -2 => VerificationFlowFailure.PersistorAccess("Command timeout occurred", sqlEx),
                2 => VerificationFlowFailure.PersistorAccess("Network error occurred", sqlEx),
                18456 => VerificationFlowFailure.PersistorAccess("Authentication failed", sqlEx),
                _ => VerificationFlowFailure.PersistorAccess($"Database error (Code: {sqlEx.Number}): {sqlEx.Message}",
                    sqlEx)
            };
        }

        return VerificationFlowFailure.PersistorAccess("Database operation failed", ex);
    }

    protected override VerificationFlowFailure CreateTimeoutFailure(TimeoutException ex)
    {
        return VerificationFlowFailure.PersistorAccess("Database operation timed out", ex);
    }

    protected override VerificationFlowFailure CreateGenericFailure(Exception ex)
    {
        return VerificationFlowFailure.Generic($"Unexpected error in membership persistor: {ex.Message}", ex);
    }

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return PersistorSupervisorStrategy.CreateStrategy();
    }
}