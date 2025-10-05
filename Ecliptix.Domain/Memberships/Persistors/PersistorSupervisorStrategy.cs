using System.Data.Common;
using Akka.Actor;
using Microsoft.Data.SqlClient;
using Serilog;

namespace Ecliptix.Domain.Memberships.Persistors;

public static class PersistorSupervisorStrategy
{
    private static readonly Dictionary<Type, int> RestartCounts = new();
    private static readonly Dictionary<Type, DateTime> LastRestartTimes = new();
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
                string actorTypeName = actorType.Name;

                return exception switch
                {
                    SqlException { Number: 18456 } => HandlePermanentFailure("Authentication failed", Directive.Stop),
                    SqlException { Number: 18486 } => HandlePermanentFailure("Account locked", Directive.Stop),

                    SqlException { Number: 4060 } => HandlePermanentFailure("Database not accessible", Directive.Stop),
                    SqlException { Number: 40197 } => HandlePermanentFailure("Service unavailable", Directive.Stop),

                    SqlException { Number: 824 or 825 } => HandlePermanentFailure("Data corruption detected", Directive.Stop),
                    SqlException { Number: 102 or 156 or 207 or 208 } => HandlePermanentFailure("Invalid SQL syntax", Directive.Stop),

                    SqlException { Number: 2 or 53 or 11001 } => HandleTransientFailure(actorType, "Network error", Directive.Restart),
                    SqlException { Number: 2146893022 } => HandleTransientFailure(actorType, "Connection timeout", Directive.Restart),

                    SqlException { Number: -2 } => HandleTransientFailure(actorType, "Command timeout", Directive.Restart),
                    TimeoutException => HandleTransientFailure(actorType, "Operation timeout", Directive.Restart),

                    SqlException { Number: 40501 or 40613 or 49918 or 49919 or 49920 } =>
                        HandleTransientFailure(actorType, "Transient Azure SQL error", Directive.Restart),

                    SqlException { Number: 1205 } => HandleTransientFailure(actorType, "Deadlock detected", Directive.Restart),
                    SqlException { Number: 2627 or 2601 } => HandleTransientFailure(actorType, "Concurrency conflict", Directive.Restart),

                    SqlException { Number: 547 or 515 } => HandleApplicationError("Constraint violation", Directive.Escalate),

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

                    Exception => HandleGenericException(actorType, exception)
                };
            });
    }

    private static Directive HandlePermanentFailure(string reason, Directive directive)
    {

        return directive;
    }

    private static Directive HandleTransientFailure(Type actorType, string reason, Directive directive)
    {
        if (ShouldThrottleRestart(actorType))
        {

            return Directive.Stop;
        }

        RecordRestart(actorType);
        return directive;
    }

    private static Directive HandleApplicationError(string reason, Directive directive)
    {

        return directive;
    }

    private static Directive HandleSystemError(string reason, Directive directive)
    {

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
        DateTime now = DateTime.UtcNow;

        CleanupOldRestartRecords(now);

        if (!RestartCounts.TryGetValue(actorType, out int count) ||
            !LastRestartTimes.TryGetValue(actorType, out DateTime lastRestart))
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
        DateTime now = DateTime.UtcNow;

        RestartCounts.TryGetValue(actorType, out int currentCount);
        RestartCounts[actorType] = currentCount + 1;
        LastRestartTimes[actorType] = now;
    }

    private static void CleanupOldRestartRecords(DateTime now)
    {
        List<Type> keysToRemove = [];
        keysToRemove.AddRange(from kvp in LastRestartTimes.ToList() where now - kvp.Value > RestartCooldown select kvp.Key);

        foreach (Type key in keysToRemove)
        {
            RestartCounts.Remove(key);
            LastRestartTimes.Remove(key);
        }
    }
}