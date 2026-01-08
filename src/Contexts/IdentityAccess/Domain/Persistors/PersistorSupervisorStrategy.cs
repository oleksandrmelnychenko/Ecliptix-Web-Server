using System.Data.Common;
using Akka.Actor;
using Npgsql;
using Serilog;

namespace Ecliptix.IdentityAccess.Domain.Persistors;

public static class PersistorSupervisorStrategy
{
    private static readonly Dictionary<Type, int> RestartCounts = new();
    private static readonly Dictionary<Type, DateTimeOffset> LastRestartTimes = new();
    private static readonly TimeSpan RestartCooldown = TimeSpan.FromMinutes(5);
    private const int MaxRestartsPerCooldown = 3;

    public static SupervisorStrategy CreateStrategy()
    {
        return new OneForOneStrategy(
            maxNrOfRetries: 10,
            withinTimeRange: TimeSpan.FromMinutes(10),
            localOnlyDecider: exception =>
            {
                Type actorType = exception.GetType();

                return exception switch
                {
                    TimeoutException => HandleTransientFailure(actorType, "Operation timeout", Directive.Restart),
                    PostgresException pgEx => HandlePostgresException(pgEx, actorType),

                    DbException => HandleTransientFailure(actorType, "Database error", Directive.Restart),

                    TaskCanceledException => HandleNormalCancellation(),
                    OperationCanceledException => HandleNormalCancellation(),

                    ArgumentNullException => HandleApplicationError("Null argument", Directive.Stop),
                    ArgumentException => HandleApplicationError("Invalid argument", Directive.Stop),
                    NullReferenceException => HandleApplicationError("Null reference", Directive.Stop),

                    InvalidOperationException when exception.Message.Contains("configuration") =>
                        HandlePermanentFailure("Configuration error", Directive.Stop),
                    InvalidOperationException when exception.Message.Contains("service") =>
                        HandlePermanentFailure("Service dependency error", Directive.Stop),

                    OutOfMemoryException => HandleSystemError("Out of memory", Directive.Escalate),
                    StackOverflowException => HandleSystemError("Stack overflow", Directive.Escalate),

                    not null => HandleGenericException(actorType, exception),
                    _ => throw new ArgumentOutOfRangeException(nameof(exception), exception, null)
                };
            });
    }

    private static Directive HandlePostgresException(PostgresException ex, Type actorType)
    {
        return ex.SqlState switch
        {
            PostgresErrorCodes.InvalidPassword or PostgresErrorCodes.InvalidAuthorizationSpecification =>
                HandlePermanentFailure("Authentication failed", Directive.Stop),
            PostgresErrorCodes.InvalidCatalogName =>
                HandlePermanentFailure("Database not accessible", Directive.Stop),
            PostgresErrorCodes.AdminShutdown or PostgresErrorCodes.CrashShutdown
                or PostgresErrorCodes.CannotConnectNow =>
                HandleTransientFailure(actorType, "Service unavailable", Directive.Restart),
            PostgresErrorCodes.DataCorrupted or PostgresErrorCodes.IndexCorrupted =>
                HandlePermanentFailure("Data corruption detected", Directive.Stop),
            PostgresErrorCodes.SyntaxError or PostgresErrorCodes.UndefinedTable
                or PostgresErrorCodes.UndefinedColumn =>
                HandlePermanentFailure("Invalid SQL syntax", Directive.Stop),
            PostgresErrorCodes.ConnectionException or PostgresErrorCodes.ConnectionDoesNotExist
                or PostgresErrorCodes.ConnectionFailure =>
                HandleTransientFailure(actorType, "Network error", Directive.Restart),
            PostgresErrorCodes.TooManyConnections =>
                HandleTransientFailure(actorType, "Service unavailable", Directive.Restart),
            PostgresErrorCodes.QueryCanceled =>
                HandleTransientFailure(actorType, "Command timeout", Directive.Restart),
            PostgresErrorCodes.DeadlockDetected =>
                HandleTransientFailure(actorType, "Deadlock detected", Directive.Restart),
            PostgresErrorCodes.SerializationFailure or PostgresErrorCodes.LockNotAvailable =>
                HandleTransientFailure(actorType, "Concurrency conflict", Directive.Restart),
            PostgresErrorCodes.UniqueViolation =>
                HandleTransientFailure(actorType, "Concurrency conflict", Directive.Restart),
            PostgresErrorCodes.ForeignKeyViolation or PostgresErrorCodes.NotNullViolation
                or PostgresErrorCodes.CheckViolation =>
                HandleApplicationError("Constraint violation", Directive.Escalate),
            _ => HandleTransientFailure(actorType, "Database error", Directive.Restart)
        };
    }

    private static Directive HandlePermanentFailure(string reason, Directive directive)
    {
        Log.Error("Permanent failure: {Reason}. Directive: {Directive}", reason, directive);
        return directive;
    }

    private static Directive HandleTransientFailure(Type actorType, string reason, Directive directive)
    {
        Log.Warning("Transient failure for {ExceptionType}: {Reason}. Directive: {Directive}", actorType.Name, reason, directive);
        if (ShouldThrottleRestart(actorType))
        {
            return Directive.Stop;
        }

        RecordRestart(actorType);
        return directive;
    }

    private static Directive HandleApplicationError(string reason, Directive directive)
    {
        Log.Error("Application error: {Reason}. Directive: {Directive}", reason, directive);
        return directive;
    }

    private static Directive HandleSystemError(string reason, Directive directive)
    {
        Log.Fatal("System error: {Reason}. Directive: {Directive}", reason, directive);
        return directive;
    }

    private static Directive HandleNormalCancellation()
    {
        return Directive.Resume;
    }

    private static Directive HandleGenericException(Type actorType, Exception exception)
    {
        if (ShouldThrottleRestart(actorType))
        {
            return Directive.Stop;
        }

        RecordRestart(actorType);
        return Directive.Restart;
    }

    private static bool ShouldThrottleRestart(Type actorType)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;

        CleanupOldRestartRecords(now);

        if (!RestartCounts.TryGetValue(actorType, out int count) ||
            !LastRestartTimes.TryGetValue(actorType, out DateTimeOffset lastRestart))
        {
            return false;
        }

        if (now - lastRestart < RestartCooldown && count >= MaxRestartsPerCooldown)
        {
            return true;
        }

        if (now - lastRestart >= RestartCooldown)
        {
            RestartCounts[actorType] = 0;
        }

        return false;
    }

    private static void RecordRestart(Type actorType)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;

        RestartCounts.TryGetValue(actorType, out int currentCount);
        RestartCounts[actorType] = currentCount + 1;
        LastRestartTimes[actorType] = now;
    }

    private static void CleanupOldRestartRecords(DateTimeOffset now)
    {
        List<Type> keysToRemove = [];
        keysToRemove.AddRange(from kvp in LastRestartTimes.ToList()
                              where now - kvp.Value > RestartCooldown
                              select kvp.Key);

        foreach (Type key in keysToRemove)
        {
            RestartCounts.Remove(key);
            LastRestartTimes.Remove(key);
        }
    }
}
