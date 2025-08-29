using System.Data;
using Akka.Actor;
using Dapper;
using Ecliptix.Domain.DbConnectionFactory;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.QueryResults;
using Ecliptix.Domain.Memberships.WorkerActors;
using Ecliptix.Domain.Utilities;
using Microsoft.Data.SqlClient;
using Serilog;

namespace Ecliptix.Domain.Memberships.Persistors;

public record CreateAuthContextActorEvent(
    byte[] ContextToken,
    Guid MembershipId, 
    Guid MobileNumberId, 
    DateTime ExpiresAt,
    string? IpAddress = null,
    string? UserAgent = null);

public record ValidateAuthContextActorEvent(byte[] ContextToken);

public record RefreshAuthContextActorEvent(byte[] ContextToken, DateTime NewExpiresAt);

public record InvalidateAuthContextActorEvent(byte[] ContextToken);

public record InvalidateAllContextsForMobileActorEvent(Guid MobileNumberId);

public record CleanupExpiredContextsActorEvent(int BatchSize = 1000, int OlderThanHours = 24);

public record UpdateAuthStateActorEvent(
    Guid MobileNumberId,
    int RecentAttempts,
    DateTime WindowStartTime,
    bool IsLocked = false,
    DateTime? LockedUntil = null);

public record GetAuthStateActorEvent(Guid MobileNumberId);

public record AuthContextQueryResult
{
    public long ContextId { get; init; }
    public Guid MembershipId { get; init; }
    public Guid MobileNumberId { get; init; }
    public bool Success { get; init; }
    public string Message { get; init; } = string.Empty;
}

public record AuthContextValidationResult
{
    public bool IsValid { get; init; }
    public string Message { get; init; } = string.Empty;
    public long? ContextId { get; init; }
    public Guid? MembershipId { get; init; }
    public Guid? MobileNumberId { get; init; }
}

public record AuthStateQueryResult
{
    public Guid MobileNumberId { get; init; }
    public int RecentAttempts { get; init; }
    public DateTime WindowStartTime { get; init; }
    public DateTime? LastAttemptTime { get; init; }
    public bool IsLocked { get; init; }
    public DateTime? LockedUntil { get; init; }
    public DateTime LastSyncTime { get; init; }
    public DateTime CreatedAt { get; init; }
    public DateTime UpdatedAt { get; init; }
}

public record BatchOperationResult
{
    public int TotalProcessed { get; init; }
    public bool Success { get; init; }
    public string Message { get; init; } = string.Empty;
}

public class AuthContextPersistorActor : PersistorBase<VerificationFlowFailure>
{
    public AuthContextPersistorActor(IDbConnectionFactory connectionFactory) 
        : base(connectionFactory)
    {
        Become(Ready);
    }

    public static Props Build(IDbConnectionFactory connectionFactory)
    {
        return Props.Create(() => new AuthContextPersistorActor(connectionFactory));
    }

    private void Ready()
    {
        Receive<CreateAuthContextActorEvent>(cmd =>
            ExecuteWithConnection(conn => CreateAuthContextAsync(conn, cmd), "CreateAuthenticationContext")
                .PipeTo(Sender));

        Receive<ValidateAuthContextActorEvent>(cmd =>
            ExecuteWithConnection(conn => ValidateAuthContextAsync(conn, cmd), "ValidateAuthenticationContext")
                .PipeTo(Sender));

        Receive<RefreshAuthContextActorEvent>(cmd =>
            ExecuteWithConnection(conn => RefreshAuthContextAsync(conn, cmd), "RefreshAuthenticationContext")
                .PipeTo(Sender));

        Receive<InvalidateAuthContextActorEvent>(cmd =>
            ExecuteWithConnection(conn => InvalidateAuthContextAsync(conn, cmd), "InvalidateAuthenticationContext")
                .PipeTo(Sender));

        Receive<InvalidateAllContextsForMobileActorEvent>(cmd =>
            ExecuteWithConnection(conn => InvalidateAllContextsForMobileAsync(conn, cmd), "InvalidateAllContextsForMobile")
                .PipeTo(Sender));

        Receive<CleanupExpiredContextsActorEvent>(cmd =>
            ExecuteWithConnection(conn => CleanupExpiredContextsAsync(conn, cmd), "CleanupExpiredContexts")
                .PipeTo(Sender));

        Receive<UpdateAuthStateActorEvent>(cmd =>
            ExecuteWithConnection(conn => UpdateAuthStateAsync(conn, cmd), "UpdateAuthenticationState")
                .PipeTo(Sender));

        Receive<GetAuthStateActorEvent>(cmd =>
            ExecuteWithConnection(conn => GetAuthStateAsync(conn, cmd), "GetAuthenticationState")
                .PipeTo(Sender));
    }

    private async Task<Result<AuthContextQueryResult, VerificationFlowFailure>> CreateAuthContextAsync(
        IDbConnection connection, CreateAuthContextActorEvent cmd)
    {
        DynamicParameters parameters = new DynamicParameters();
        parameters.Add("@ContextToken", cmd.ContextToken);
        parameters.Add("@MembershipId", cmd.MembershipId);
        parameters.Add("@MobileNumberId", cmd.MobileNumberId);
        parameters.Add("@ExpiresAt", cmd.ExpiresAt);
        parameters.Add("@IpAddress", cmd.IpAddress);
        parameters.Add("@UserAgent", cmd.UserAgent);

        AuthContextQueryResult? result = await connection.QuerySingleOrDefaultAsync<AuthContextQueryResult>(
            "dbo.CreateAuthenticationContext",
            parameters,
            commandType: CommandType.StoredProcedure
        );

        if (result == null)
        {
            Log.Error("CreateAuthenticationContext stored procedure returned null for MembershipId {MembershipId}", 
                cmd.MembershipId);
            return Result<AuthContextQueryResult, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess("Failed to create authentication context - no result returned"));
        }

        return result.Success
            ? Result<AuthContextQueryResult, VerificationFlowFailure>.Ok(result)
            : Result<AuthContextQueryResult, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess(result.Message));
    }

    private async Task<Result<AuthContextValidationResult, VerificationFlowFailure>> ValidateAuthContextAsync(
        IDbConnection connection, ValidateAuthContextActorEvent cmd)
    {
        DynamicParameters parameters = new DynamicParameters();
        parameters.Add("@ContextToken", cmd.ContextToken);

        AuthContextValidationResult? result = await connection.QuerySingleOrDefaultAsync<AuthContextValidationResult>(
            "dbo.ValidateAuthenticationContext",
            parameters,
            commandType: CommandType.StoredProcedure
        );

        if (result == null)
        {
            Log.Error("ValidateAuthenticationContext stored procedure returned null for token");
            return Result<AuthContextValidationResult, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess("Failed to validate authentication context - no result returned"));
        }

        return Result<AuthContextValidationResult, VerificationFlowFailure>.Ok(result);
    }

    private async Task<Result<BatchOperationResult, VerificationFlowFailure>> RefreshAuthContextAsync(
        IDbConnection connection, RefreshAuthContextActorEvent cmd)
    {
        DynamicParameters parameters = new DynamicParameters();
        parameters.Add("@ContextToken", cmd.ContextToken);
        parameters.Add("@NewExpiresAt", cmd.NewExpiresAt);

        BatchOperationResult? result = await connection.QuerySingleOrDefaultAsync<BatchOperationResult>(
            "dbo.RefreshAuthenticationContext",
            parameters,
            commandType: CommandType.StoredProcedure
        );

        if (result == null)
        {
            Log.Error("RefreshAuthenticationContext stored procedure returned null");
            return Result<BatchOperationResult, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess("Failed to refresh authentication context - no result returned"));
        }

        return Result<BatchOperationResult, VerificationFlowFailure>.Ok(result);
    }

    private async Task<Result<BatchOperationResult, VerificationFlowFailure>> InvalidateAuthContextAsync(
        IDbConnection connection, InvalidateAuthContextActorEvent cmd)
    {
        DynamicParameters parameters = new DynamicParameters();
        parameters.Add("@ContextToken", cmd.ContextToken);

        BatchOperationResult? result = await connection.QuerySingleOrDefaultAsync<BatchOperationResult>(
            "dbo.InvalidateAuthenticationContext",
            parameters,
            commandType: CommandType.StoredProcedure
        );

        if (result == null)
        {
            Log.Error("InvalidateAuthenticationContext stored procedure returned null");
            return Result<BatchOperationResult, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess("Failed to invalidate authentication context - no result returned"));
        }

        return Result<BatchOperationResult, VerificationFlowFailure>.Ok(result);
    }

    private async Task<Result<BatchOperationResult, VerificationFlowFailure>> InvalidateAllContextsForMobileAsync(
        IDbConnection connection, InvalidateAllContextsForMobileActorEvent cmd)
    {
        DynamicParameters parameters = new DynamicParameters();
        parameters.Add("@MobileNumberId", cmd.MobileNumberId);

        BatchOperationResult? result = await connection.QuerySingleOrDefaultAsync<BatchOperationResult>(
            "dbo.InvalidateAllContextsForMobile",
            parameters,
            commandType: CommandType.StoredProcedure
        );

        if (result == null)
        {
            Log.Error("InvalidateAllContextsForMobile stored procedure returned null for MobileNumberId {MobileNumberId}", 
                cmd.MobileNumberId);
            return Result<BatchOperationResult, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess("Failed to invalidate contexts for mobile - no result returned"));
        }

        return Result<BatchOperationResult, VerificationFlowFailure>.Ok(result);
    }

    private async Task<Result<BatchOperationResult, VerificationFlowFailure>> CleanupExpiredContextsAsync(
        IDbConnection connection, CleanupExpiredContextsActorEvent cmd)
    {
        DynamicParameters parameters = new DynamicParameters();
        parameters.Add("@BatchSize", cmd.BatchSize);
        parameters.Add("@OlderThanHours", cmd.OlderThanHours);

        BatchOperationResult? result = await connection.QuerySingleOrDefaultAsync<BatchOperationResult>(
            "dbo.CleanupExpiredContexts",
            parameters,
            commandType: CommandType.StoredProcedure
        );

        if (result == null)
        {
            Log.Error("CleanupExpiredContexts stored procedure returned null");
            return Result<BatchOperationResult, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess("Failed to cleanup expired contexts - no result returned"));
        }

        Log.Information("Cleaned up {ProcessedCount} expired authentication contexts", result.TotalProcessed);
        return Result<BatchOperationResult, VerificationFlowFailure>.Ok(result);
    }

    private async Task<Result<BatchOperationResult, VerificationFlowFailure>> UpdateAuthStateAsync(
        IDbConnection connection, UpdateAuthStateActorEvent cmd)
    {
        DynamicParameters parameters = new DynamicParameters();
        parameters.Add("@MobileNumberId", cmd.MobileNumberId);
        parameters.Add("@RecentAttempts", cmd.RecentAttempts);
        parameters.Add("@WindowStartTime", cmd.WindowStartTime);
        parameters.Add("@IsLocked", cmd.IsLocked);
        parameters.Add("@LockedUntil", cmd.LockedUntil);

        BatchOperationResult? result = await connection.QuerySingleOrDefaultAsync<BatchOperationResult>(
            "dbo.UpdateAuthenticationState",
            parameters,
            commandType: CommandType.StoredProcedure
        );

        if (result == null)
        {
            Log.Error("UpdateAuthenticationState stored procedure returned null for MobileNumberId {MobileNumberId}", 
                cmd.MobileNumberId);
            return Result<BatchOperationResult, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess("Failed to update authentication state - no result returned"));
        }

        return Result<BatchOperationResult, VerificationFlowFailure>.Ok(result);
    }

    private async Task<Result<AuthStateQueryResult, VerificationFlowFailure>> GetAuthStateAsync(
        IDbConnection connection, GetAuthStateActorEvent cmd)
    {
        DynamicParameters parameters = new DynamicParameters();
        parameters.Add("@MobileNumberId", cmd.MobileNumberId);

        AuthStateQueryResult? result = await connection.QuerySingleOrDefaultAsync<AuthStateQueryResult>(
            "dbo.GetAuthenticationState",
            parameters,
            commandType: CommandType.StoredProcedure
        );

        if (result == null)
        {
            Log.Warning("GetAuthenticationState returned null for MobileNumberId {MobileNumberId} - this may be normal for new mobile numbers", 
                cmd.MobileNumberId);

            result = new AuthStateQueryResult
            {
                MobileNumberId = cmd.MobileNumberId,
                RecentAttempts = 0,
                WindowStartTime = DateTime.UtcNow,
                LastAttemptTime = null,
                IsLocked = false,
                LockedUntil = null,
                LastSyncTime = DateTime.UtcNow,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };
        }

        return Result<AuthStateQueryResult, VerificationFlowFailure>.Ok(result);
    }

    protected override VerificationFlowFailure MapDbException(System.Data.Common.DbException ex)
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
        return VerificationFlowFailure.Generic($"Unexpected error in auth context persistor: {ex.Message}", ex);
    }

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return PersistorSupervisorStrategy.CreateStrategy();
    }
}