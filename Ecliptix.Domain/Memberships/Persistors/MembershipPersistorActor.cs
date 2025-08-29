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
using Ecliptix.Domain.Utilities;
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
        DynamicParameters parameters = new DynamicParameters();
        parameters.Add("@PhoneNumber", cmd.MobileNumber);

        LoginMembershipResult? result = await connection.QuerySingleOrDefaultAsync<LoginMembershipResult>(
            "dbo.LoginMembership",
            parameters,
            commandType: CommandType.StoredProcedure
        );

        if (result is null)
        {
            Log.Error("LoginMembership stored procedure returned null for MobileNumber {MaskedMobileNumber}", MaskMobileNumber(cmd.MobileNumber));
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess("Login membership failed - stored procedure returned null result"));
        }

        if (int.TryParse(result.Outcome, out int _))
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.RateLimitExceeded(result.Outcome));

        return result.Outcome switch
        {
            "success" when result.MembershipUniqueId.HasValue && !string.IsNullOrEmpty(result.Status) =>
                MapActivityStatus(result.Status).Match(
                    status => Result<MembershipQueryRecord, VerificationFlowFailure>.Ok(
                        new MembershipQueryRecord
                        {
                            UniqueIdentifier = result.MembershipUniqueId.Value,
                            ActivityStatus = status,
                            CreationStatus = Membership.Types.CreationStatus.OtpVerified,
                            SecureKey = result.SecureKey
                        }),
                    () => Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.ActivityStatusInvalid))
                ),

            string error when IsKnownLoginError(error) =>
                Result<MembershipQueryRecord, VerificationFlowFailure>.Err(VerificationFlowFailure.Validation(error)),

            string outcome =>
                Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.PersistorAccess(outcome))
        };
    }

    private async Task<Result<MembershipQueryRecord, VerificationFlowFailure>> UpdateMembershipSecureKeyAsync(
        IDbConnection connection, UpdateMembershipSecureKeyEvent cmd)
    {
        DynamicParameters parameters = new DynamicParameters();
        parameters.Add("@MembershipUniqueId", cmd.MembershipIdentifier);
        parameters.Add("@SecureKey", cmd.SecureKey);

        UpdateSecureKeyResult? result = await connection.QuerySingleOrDefaultAsync<UpdateSecureKeyResult>(
            "dbo.UpdateMembershipSecureKey",
            parameters,
            commandType: CommandType.StoredProcedure
        );

        if (result is null)
        {
            Log.Error("UpdateMembershipSecureKey stored procedure returned null for MembershipUniqueId {MembershipId}", cmd.MembershipIdentifier);
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess("Update membership secure key failed - stored procedure returned null result"));
        }

        if (!result.Success)
        {
            Log.Warning("UpdateMembershipSecureKey failed for MembershipUniqueId {MembershipId}: {Message}", 
                cmd.MembershipIdentifier, result.Message);
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Validation($"Secure key update failed: {result.Message}"));
        }

        if (!result.MembershipUniqueId.HasValue || string.IsNullOrEmpty(result.Status) ||
            string.IsNullOrEmpty(result.CreationStatus))
        {
            Log.Error("UpdateMembershipSecureKey returned success but missing data - MembershipId: {HasId}, Status: {Status}, CreationStatus: {CreationStatus}",
                result.MembershipUniqueId.HasValue, result.Status, result.CreationStatus);
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess("Secure key update succeeded but returned incomplete data"));
        }

        return MapActivityStatus(result.Status).Match(
            status => Result<MembershipQueryRecord, VerificationFlowFailure>.Ok(
                new MembershipQueryRecord
                {
                    UniqueIdentifier = result.MembershipUniqueId.Value,
                    ActivityStatus = status,
                    CreationStatus = MembershipCreationStatusHelper.GetCreationStatusEnum(result.CreationStatus)
                }),
            () => Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.ActivityStatusInvalid))
        );
    }

    private static async Task<Result<MembershipQueryRecord, VerificationFlowFailure>> CreateMembershipAsync(
        IDbConnection connection, CreateMembershipActorEvent cmd)
    {
        DynamicParameters parameters = new DynamicParameters();
        parameters.Add("@FlowUniqueId", cmd.VerificationFlowIdentifier);
        parameters.Add("@ConnectionId", (long)cmd.ConnectId);
        parameters.Add("@OtpUniqueId", cmd.OtpIdentifier);
        parameters.Add("@CreationStatus", MembershipCreationStatusHelper.GetCreationStatusString(cmd.CreationStatus));

        CreateMembershipResult? result = await connection.QuerySingleOrDefaultAsync<CreateMembershipResult>(
            "dbo.CreateMembership",
            parameters,
            commandType: CommandType.StoredProcedure);

        if (result is null)
        {
            Log.Error("CreateMembership stored procedure returned null for FlowUniqueId {FlowId}, ConnectId {ConnectId}",
                cmd.VerificationFlowIdentifier, cmd.ConnectId);
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess("Create membership failed - stored procedure returned null result"));
        }

        if (int.TryParse(result.Outcome, out int rateLimitSeconds))
        {
            Log.Warning("CreateMembership rate limit exceeded for FlowUniqueId {FlowId}: {RateLimitSeconds} seconds",
                cmd.VerificationFlowIdentifier, rateLimitSeconds);
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

    private static Result<MembershipQueryRecord, VerificationFlowFailure> CreateValidationError(CreateMembershipActorEvent cmd, string error)
    {
        Log.Warning("CreateMembership validation error for FlowUniqueId {FlowId}: {Error}",
            cmd.VerificationFlowIdentifier, error);
        return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(VerificationFlowFailure.Validation(error));
    }

    private static Result<MembershipQueryRecord, VerificationFlowFailure> CreatePersistorAccessError(CreateMembershipActorEvent cmd, string outcome)
    {
        Log.Error("CreateMembership unexpected outcome for FlowUniqueId {FlowId}: {Outcome}",
            cmd.VerificationFlowIdentifier, outcome);
        return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
            VerificationFlowFailure.PersistorAccess($"Membership creation failed: {outcome}"));
    }

    private static bool IsKnownLoginError(string outcome)
    {
        return outcome is VerificationFlowMessageKeys.InvalidSecureKey or
            VerificationFlowMessageKeys.InactiveMembership or
            VerificationFlowMessageKeys.PhoneNumberCannotBeEmpty or
            VerificationFlowMessageKeys.SecureKeyCannotBeEmpty or
            VerificationFlowMessageKeys.SecureKeyNotSet or
            VerificationFlowMessageKeys.PhoneNotFound or
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
        return VerificationFlowFailure.Generic($"Unexpected error in membership persistor: {ex.Message}", ex);
    }

    private static string MaskMobileNumber(string mobileNumber)
    {
        if (string.IsNullOrEmpty(mobileNumber) || mobileNumber.Length < 4)
            return "***";

        return $"{mobileNumber[..3]}****{mobileNumber[^2..]}";
    }

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return PersistorSupervisorStrategy.CreateStrategy();
    }
}