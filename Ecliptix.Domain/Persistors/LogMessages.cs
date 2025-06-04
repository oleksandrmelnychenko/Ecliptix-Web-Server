namespace Ecliptix.Domain.Persistors;

public static class LogMessages
{
    public const string OperationCompleted = "Database operation {OperationName} completed successfully in {ElapsedMs}ms";
    public const string OperationFailed = "Database operation {OperationName} failed: {Error}";
    public const string DatabaseError = "Database error in operation {OperationName} after {ElapsedMs}ms: {SqlState} - {Message}";
    public const string TimeoutError = "Timeout in operation {OperationName} after {ElapsedMs}ms";
    public const string UnexpectedError = "Unexpected error in operation {OperationName} after {ElapsedMs}ms";
}
