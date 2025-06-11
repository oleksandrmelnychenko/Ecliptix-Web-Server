using System.Data;
using System.Data.Common;
using Akka.Actor;
using Dapper;
using Ecliptix.Domain.DbConnectionFactory;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Persistors;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Logging;
using static System.String;

namespace Ecliptix.Domain.Memberships.Persistors;

internal class LoginMembershipResult
{
    public Guid? MembershipUniqueId { get; set; }
    public string? Status { get; set; }
    public string Outcome { get; set; } = string.Empty;
}

internal class UpdateSecureKeyResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public Guid? MembershipUniqueId { get; set; }
    public string? Status { get; set; }
    public string? CreationStatus { get; set; }
}

internal class CreateMembershipResult
{
    public Guid? MembershipUniqueId { get; set; }
    public string? Status { get; set; }
    public string? CreationStatus { get; set; }
    public string Outcome { get; set; } = Empty;
}

public class MembershipPersistorActor : PersistorBase<VerificationFlowFailure>
{
    public MembershipPersistorActor(
        IDbConnectionFactory connectionFactory,
        ILogger<MembershipPersistorActor> logger)
        : base(connectionFactory, logger)
    {
        Become(Ready);
    }

    public static Props Build(IDbConnectionFactory connectionFactory,
        ILogger<MembershipPersistorActor> logger) =>
        Props.Create(() => new MembershipPersistorActor(connectionFactory, logger));

    private void Ready()
    {
        Receive<UpdateMembershipSecureKeyEvent>(cmd =>
            ExecuteWithConnection(conn => UpdateMembershipSecureKeyAsync(conn, cmd), "UpdateMembershipSecureKey")
                .PipeTo(Self, sender: Sender));

        Receive<CreateMembershipActorEvent>(cmd =>
            ExecuteWithConnection(conn => CreateMembershipAsync(conn, cmd), "CreateMembership")
                .PipeTo(Self, sender: Sender));

        Receive<SignInMembershipActorEvent>(cmd =>
            ExecuteWithConnection(conn => SignInMembershipAsync(conn, cmd), "LoginMembership")
                .PipeTo(Self, sender: Sender));
    }

    private async Task<Result<MembershipQueryRecord, VerificationFlowFailure>> SignInMembershipAsync(
        IDbConnection connection, SignInMembershipActorEvent cmd)
    {
        var parameters = new DynamicParameters();
        parameters.Add("@PhoneNumber", cmd.PhoneNumber);
        parameters.Add("@SecureKey", cmd.SecureKey);

        var result = await connection.QuerySingleOrDefaultAsync<LoginMembershipResult>(
            "dbo.LoginMembership",
            parameters,
            commandType: CommandType.StoredProcedure
        );

        if (result is null)
        {
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.DataAccess));
        }

        if (int.TryParse(result.Outcome, out int _))
        {
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.RateLimitExceeded(VerificationFlowMessageKeys.TooManySigninAttempts));
        }

        return result.Outcome switch
        {
            "success" when result.MembershipUniqueId.HasValue && !IsNullOrEmpty(result.Status) =>
                MapActivityStatus(result.Status).Match<Result<MembershipQueryRecord, VerificationFlowFailure>>(
                    status => Result<MembershipQueryRecord, VerificationFlowFailure>.Ok(
                        new MembershipQueryRecord
                        {
                            UniqueIdentifier = result.MembershipUniqueId.Value,
                            ActivityStatus = status,
                            CreationStatus = Membership.Types.CreationStatus.OtpVerified
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
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.DataAccess));
        }

        if (!result.Success)
        {
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Validation(result.Message));
        }

        if (!result.MembershipUniqueId.HasValue || IsNullOrEmpty(result.Status) || IsNullOrEmpty(result.CreationStatus))
        {
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess("Procedure returned success but missing required data."));
        }

        return MapActivityStatus(result.Status).Match<Result<MembershipQueryRecord, VerificationFlowFailure>>(
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

    private async Task<Result<MembershipQueryRecord, VerificationFlowFailure>> CreateMembershipAsync(
        IDbConnection connection, CreateMembershipActorEvent cmd)
    {
        DynamicParameters parameters = new();
        parameters.Add("@FlowUniqueId", cmd.SessionIdentifier);
        parameters.Add("@ConnectionId", (long)cmd.ConnectId);
        parameters.Add("@OtpUniqueId", cmd.OtpIdentifier);
        parameters.Add("@CreationStatus", MembershipCreationStatusHelper.GetCreationStatusString(cmd.CreationStatus));

        CreateMembershipResult? result = await connection.QuerySingleOrDefaultAsync<CreateMembershipResult>(
            "dbo.CreateMembership",
            parameters,
            commandType: CommandType.StoredProcedure);

        if (result is null)
        {
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.DataAccess));
        }

        if (int.TryParse(result.Outcome, out int _))
        {
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.RateLimitExceeded(VerificationFlowMessageKeys.TooManyMembershipAttempts));
        }

        return result.Outcome switch
        {
            VerificationFlowMessageKeys.Created
                or VerificationFlowMessageKeys.MembershipAlreadyExists when result.MembershipUniqueId.HasValue &&
                                                                            !IsNullOrEmpty(result.Status) &&
                                                                            !IsNullOrEmpty(result.CreationStatus) =>
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

    private static bool IsKnownLoginError(string outcome) =>
        outcome is VerificationFlowMessageKeys.InvalidSecureKey or
            VerificationFlowMessageKeys.InactiveMembership or
            VerificationFlowMessageKeys.PhoneNumberCannotBeEmpty or
            VerificationFlowMessageKeys.SecureKeyCannotBeEmpty or
            VerificationFlowMessageKeys.SecureKeyNotSet or
            VerificationFlowMessageKeys.PhoneNotFound or
            VerificationFlowMessageKeys.MembershipNotFound;

    private static bool IsKnownCreationError(string outcome) =>
        outcome is VerificationFlowMessageKeys.CreateMembershipVerificationFlowNotFound;

    private static Option<Membership.Types.ActivityStatus> MapActivityStatus(string? statusStr)
    {
        if (IsNullOrEmpty(statusStr) || !MembershipStatusMap.TryGetValue(statusStr, out var status))
        {
            return Option<Membership.Types.ActivityStatus>.None;
        }

        return Option<Membership.Types.ActivityStatus>.Some(status);
    }

    private static readonly Dictionary<string, Membership.Types.ActivityStatus> MembershipStatusMap = new()
    {
        ["active"] = Membership.Types.ActivityStatus.Active,
        ["inactive"] = Membership.Types.ActivityStatus.Inactive,
    };

    protected override IDbDataParameter CreateParameter(string name, object value)
    {
        return new SqlParameter(name, value);
    }

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