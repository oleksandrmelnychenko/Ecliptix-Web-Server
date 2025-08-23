using System.Data.Common;
using Ecliptix.Domain.Utilities;
using Grpc.Core;
using Microsoft.Data.SqlClient;

namespace Ecliptix.Domain.Memberships.Persistors;

public enum PersistorFailureType
{
    TransientDatabase,
    PermanentDatabase,
    ConnectionTimeout,
    CommandTimeout,
    AuthenticationFailed,
    DatabaseUnavailable,
    ConstraintViolation,
    ConcurrencyConflict,
    InvalidQuery,
    DataCorruption,
    NetworkFailure,
    Generic
}

public sealed record PersistorFailure(
    PersistorFailureType FailureType,
    string Message,
    string OperationName,
    Exception? InnerException = null)
    : FailureBase(Message, InnerException)
{
    public bool IsTransient => FailureType switch
    {
        PersistorFailureType.TransientDatabase => true,
        PersistorFailureType.ConnectionTimeout => true,
        PersistorFailureType.CommandTimeout => true,
        PersistorFailureType.DatabaseUnavailable => true,
        PersistorFailureType.NetworkFailure => true,
        _ => false
    };

    public bool ShouldRestartActor => FailureType switch
    {
        PersistorFailureType.TransientDatabase => true,
        PersistorFailureType.ConnectionTimeout => true,
        PersistorFailureType.NetworkFailure => true,
        _ => false
    };

    public bool ShouldStopActor => FailureType switch
    {
        PersistorFailureType.AuthenticationFailed => true,
        PersistorFailureType.DataCorruption => true,
        PersistorFailureType.InvalidQuery => true,
        _ => false
    };

    public TimeSpan RetryDelay => FailureType switch
    {
        PersistorFailureType.TransientDatabase => TimeSpan.FromMilliseconds(500),
        PersistorFailureType.ConnectionTimeout => TimeSpan.FromSeconds(1),
        PersistorFailureType.CommandTimeout => TimeSpan.FromSeconds(2),
        PersistorFailureType.DatabaseUnavailable => TimeSpan.FromSeconds(5),
        PersistorFailureType.NetworkFailure => TimeSpan.FromSeconds(1),
        _ => TimeSpan.Zero
    };

    public static PersistorFailure FromDbException(DbException exception, string operationName)
    {
        if (exception is SqlException sqlException)
        {
            return sqlException.Number switch
            {
                // Connection and network errors
                2 => new PersistorFailure(PersistorFailureType.NetworkFailure, 
                    $"SQL Server not found or network error in {operationName}", operationName, exception),
                53 => new PersistorFailure(PersistorFailureType.NetworkFailure, 
                    $"Network path not found during {operationName}", operationName, exception),
                11001 => new PersistorFailure(PersistorFailureType.NetworkFailure, 
                    $"Host not found during {operationName}", operationName, exception),

                // Authentication errors
                18456 => new PersistorFailure(PersistorFailureType.AuthenticationFailed, 
                    $"Authentication failed for {operationName}", operationName, exception),
                18486 => new PersistorFailure(PersistorFailureType.AuthenticationFailed, 
                    $"Account locked for {operationName}", operationName, exception),

                // Timeout errors
                -2 => new PersistorFailure(PersistorFailureType.CommandTimeout, 
                    $"Command timeout during {operationName}", operationName, exception),
                2146893022 => new PersistorFailure(PersistorFailureType.ConnectionTimeout, 
                    $"Connection timeout during {operationName}", operationName, exception),

                // Constraint violations
                547 => new PersistorFailure(PersistorFailureType.ConstraintViolation, 
                    $"Foreign key constraint violation in {operationName}: {exception.Message}", operationName, exception),
                515 => new PersistorFailure(PersistorFailureType.ConstraintViolation, 
                    $"NOT NULL constraint violation in {operationName}: {exception.Message}", operationName, exception),

                // Concurrency issues
                2627 or 2601 => new PersistorFailure(PersistorFailureType.ConcurrencyConflict, 
                    $"Unique constraint violation in {operationName}: {exception.Message}", operationName, exception),
                1205 => new PersistorFailure(PersistorFailureType.ConcurrencyConflict, 
                    $"Deadlock detected in {operationName}", operationName, exception),

                // Database unavailable
                4060 => new PersistorFailure(PersistorFailureType.DatabaseUnavailable, 
                    $"Database not accessible during {operationName}", operationName, exception),
                40197 => new PersistorFailure(PersistorFailureType.DatabaseUnavailable, 
                    $"Service unavailable during {operationName}", operationName, exception),

                // Transient errors (Azure SQL specific)
                40501 or 40613 or 49918 or 49919 or 49920 => new PersistorFailure(PersistorFailureType.TransientDatabase, 
                    $"Transient database error in {operationName}: {exception.Message}", operationName, exception),

                // Query/syntax errors
                102 or 156 or 207 or 208 => new PersistorFailure(PersistorFailureType.InvalidQuery, 
                    $"SQL syntax error in {operationName}: {exception.Message}", operationName, exception),

                // Data corruption
                824 or 825 => new PersistorFailure(PersistorFailureType.DataCorruption, 
                    $"Data corruption detected in {operationName}", operationName, exception),

                // Default case
                _ => new PersistorFailure(PersistorFailureType.PermanentDatabase, 
                    $"SQL Server error {sqlException.Number} in {operationName}: {exception.Message}", operationName, exception)
            };
        }

        return new PersistorFailure(PersistorFailureType.Generic, 
            $"Database error in {operationName}: {exception.Message}", operationName, exception);
    }

    public static PersistorFailure FromTimeoutException(TimeoutException exception, string operationName)
    {
        return new PersistorFailure(PersistorFailureType.CommandTimeout,
            $"Operation {operationName} timed out: {exception.Message}", operationName, exception);
    }

    public static PersistorFailure FromGenericException(Exception exception, string operationName)
    {
        return new PersistorFailure(PersistorFailureType.Generic,
            $"Unexpected error in {operationName}: {exception.Message}", operationName, exception);
    }

    public static PersistorFailure NullResult(string operationName, string details)
    {
        return new PersistorFailure(PersistorFailureType.DataCorruption,
            $"Operation {operationName} returned null: {details}", operationName);
    }

    public static PersistorFailure InvalidResult(string operationName, string details)
    {
        return new PersistorFailure(PersistorFailureType.DataCorruption,
            $"Operation {operationName} returned invalid data: {details}", operationName);
    }

    public override Status ToGrpcStatus()
    {
        StatusCode code = FailureType switch
        {
            PersistorFailureType.AuthenticationFailed => StatusCode.Unauthenticated,
            PersistorFailureType.ConstraintViolation => StatusCode.InvalidArgument,
            PersistorFailureType.ConcurrencyConflict => StatusCode.Aborted,
            PersistorFailureType.ConnectionTimeout => StatusCode.Unavailable,
            PersistorFailureType.CommandTimeout => StatusCode.DeadlineExceeded,
            PersistorFailureType.DatabaseUnavailable => StatusCode.Unavailable,
            PersistorFailureType.TransientDatabase => StatusCode.Unavailable,
            PersistorFailureType.NetworkFailure => StatusCode.Unavailable,
            PersistorFailureType.InvalidQuery => StatusCode.Internal,
            PersistorFailureType.DataCorruption => StatusCode.DataLoss,
            PersistorFailureType.PermanentDatabase => StatusCode.Internal,
            PersistorFailureType.Generic => StatusCode.Internal,
            _ => StatusCode.Unknown
        };

        return new Status(code, Message);
    }

    public override object ToStructuredLog()
    {
        return new
        {
            FailureType = FailureType.ToString(),
            OperationName,
            Message,
            InnerException = InnerException?.ToString(),
            Timestamp,
            IsTransient,
            ShouldRestartActor,
            ShouldStopActor,
            RetryDelay = RetryDelay.TotalMilliseconds
        };
    }
}