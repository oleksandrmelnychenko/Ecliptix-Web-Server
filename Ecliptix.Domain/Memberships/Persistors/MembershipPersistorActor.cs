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
        parameters.Add("@PhoneNumber", cmd.PhoneNumber);

        LoginMembershipResult? result = await connection.QuerySingleOrDefaultAsync<LoginMembershipResult>(
            "dbo.LoginMembership",
            parameters,
            commandType: CommandType.StoredProcedure
        );

        if (result is null)
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.DataAccess));

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

            var error when IsKnownLoginError(error) =>
                Result<MembershipQueryRecord, VerificationFlowFailure>.Err(VerificationFlowFailure.Validation(error)),

            var outcome =>
                Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.PersistorAccess(outcome))
        };
    }

    private async Task<Result<MembershipQueryRecord, VerificationFlowFailure>> UpdateMembershipSecureKeyAsync(
        IDbConnection connection, UpdateMembershipSecureKeyEvent cmd)
    {
        DynamicParameters parameters = new();
        parameters.Add("@MembershipUniqueId", cmd.MembershipIdentifier);
        parameters.Add("@SecureKey", cmd.SecureKey);

        UpdateSecureKeyResult? result = await connection.QuerySingleOrDefaultAsync<UpdateSecureKeyResult>(
            "dbo.UpdateMembershipSecureKey",
            parameters,
            commandType: CommandType.StoredProcedure
        );

        if (result is null)
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.DataAccess));

        if (!result.Success)
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Validation(result.Message));

        if (!result.MembershipUniqueId.HasValue || string.IsNullOrEmpty(result.Status) ||
            string.IsNullOrEmpty(result.CreationStatus))
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess("Procedure returned success but missing required data."));

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
        DynamicParameters parameters = new();
        parameters.Add("@FlowUniqueId", cmd.VerificationFlowIdentifier);
        parameters.Add("@ConnectionId", (long)cmd.ConnectId);
        parameters.Add("@OtpUniqueId", cmd.OtpIdentifier);
        parameters.Add("@CreationStatus", MembershipCreationStatusHelper.GetCreationStatusString(cmd.CreationStatus));

        CreateMembershipResult? result = await connection.QuerySingleOrDefaultAsync<CreateMembershipResult>(
            "dbo.CreateMembership",
            parameters,
            commandType: CommandType.StoredProcedure);

        if (result is null)
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.DataAccess));

        if (int.TryParse(result.Outcome, out int _))
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.RateLimitExceeded(VerificationFlowMessageKeys.TooManyMembershipAttempts));

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

            var error when IsKnownCreationError(error) =>
                Result<MembershipQueryRecord, VerificationFlowFailure>.Err(VerificationFlowFailure.Validation(error)),

            var outcome =>
                Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.PersistorAccess(outcome))
        };
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