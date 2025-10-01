using System.Collections.Concurrent;
using Akka.Actor;
using Ecliptix.Utilities.Configuration;
using Serilog;

namespace Ecliptix.Domain.Memberships.WorkerActors;

public record GetOrCreateAuthContext(uint ConnectId, string MobileNumber);
public record RemoveAuthContext(uint ConnectId);

public record AttemptAuthentication(string MobileNumber);
public record EstablishContext(Guid MembershipId, Guid MobileNumberId, byte[] ContextToken);
public record AuthContextEstablished(byte[] ContextToken, DateTime ExpiresAt);

public record ValidateContext(byte[] ContextToken);
public record GetContextInfo;

public abstract record AuthResult
{
    public record Proceed : AuthResult;
    public record RateLimited(DateTime LockedUntil) : AuthResult;
    public record InvalidContext(string Reason) : AuthResult;
    public record ValidContext(Guid MembershipId, Guid MobileNumberId) : AuthResult;
}

public abstract record ContextInfo
{
    public record NotEstablished : ContextInfo;
    public record Expired : ContextInfo;
    public record Active(Guid MembershipId, Guid MobileNumberId, DateTime ExpiresAt) : ContextInfo;
}

public class AuthenticationStateManager : ReceiveActor
{
    private readonly ConcurrentDictionary<uint, IActorRef> _activeContexts = new();
    private readonly ConcurrentDictionary<uint, DateTime> _lastActivity = new();

    private const int MaxConcurrentContexts = 10000;
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan MetricsInterval = TimeSpan.FromMinutes(5);

    private ICancelable? _cleanupTimer;
    private ICancelable? _metricsTimer;

    public AuthenticationStateManager()
    {
        Become(Ready);
    }

    public static Props Build()
    {
        return Props.Create(() => new AuthenticationStateManager());
    }

    protected override void PreStart()
    {
        base.PreStart();

        _cleanupTimer = Context.System.Scheduler.ScheduleTellRepeatedlyCancelable(
            CleanupInterval, 
            CleanupInterval, 
            Self, 
            new CleanupIdleContexts(), 
            ActorRefs.NoSender);

        _metricsTimer = Context.System.Scheduler.ScheduleTellRepeatedlyCancelable(
            MetricsInterval,
            MetricsInterval,
            Self,
            new LogMetrics(),
            ActorRefs.NoSender);

        Log.Information("AuthenticationStateManager started - max contexts: {MaxContexts}, idle timeout: {IdleTimeout}", 
            MaxConcurrentContexts, IdleTimeout);
    }

    protected override void PostStop()
    {
        _cleanupTimer?.Cancel();
        _metricsTimer?.Cancel();

        Log.Information("AuthenticationStateManager stopped - managed {ActiveContexts} contexts", 
            _activeContexts.Count);

        base.PostStop();
    }

    private void Ready()
    {
        Receive<GetOrCreateAuthContext>(msg =>
        {
            UpdateLastActivity(msg.ConnectId);

            if (_activeContexts.Count >= MaxConcurrentContexts)
            {
                EvictOldestIdleActors(100); 
            }

            if (!_activeContexts.TryGetValue(msg.ConnectId, out IActorRef? actor))
            {
                actor = Context.ActorOf(
                    AuthenticationContextActor.Build(msg.ConnectId, Self),
                    $"auth-context-{msg.ConnectId}"
                );

                Context.Watch(actor);

                _activeContexts.TryAdd(msg.ConnectId, actor);
                _lastActivity.TryAdd(msg.ConnectId, DateTime.UtcNow);

                Log.Debug("Created AuthenticationContextActor for connectId {ConnectId}, mobile {MaskedMobileNumber} - total contexts: {Total}", 
                    msg.ConnectId, MaskMobileNumber(msg.MobileNumber), _activeContexts.Count);
            }
            else
            {
                Log.Debug("Reusing existing AuthenticationContextActor for connectId {ConnectId}", msg.ConnectId);
            }

            Sender.Tell(actor);
        });

        Receive<RemoveAuthContext>(msg =>
        {
            if (_activeContexts.TryRemove(msg.ConnectId, out IActorRef? actor))
            {
                _lastActivity.TryRemove(msg.ConnectId, out _);
                Context.Unwatch(actor);
                Context.Stop(actor);

                Log.Debug("Removed AuthenticationContextActor for connectId {ConnectId} - remaining contexts: {Remaining}", 
                    msg.ConnectId, _activeContexts.Count);
            }
        });

        Receive<CleanupIdleContexts>(_ =>
        {
            int cleanedCount = CleanupIdleActors();
            if (cleanedCount > 0)
            {
                Log.Information("Cleaned up {CleanedCount} idle authentication context actors", cleanedCount);
            }
        });

        Receive<LogMetrics>(_ =>
        {
            int expiredCount = CheckForExpiredContexts();
            Log.Information("AuthenticationStateManager metrics - Active contexts: {ActiveContexts}, Expired cleaned: {ExpiredCount}, Memory usage: ~{MemoryMB}MB", 
                _activeContexts.Count, expiredCount, EstimateMemoryUsageMb());
        });

        Receive<Terminated>(terminated =>
        {
            uint connectIdToRemove = _activeContexts
                .Where(kvp => kvp.Value.Equals(terminated.ActorRef))
                .Select(kvp => kvp.Key)
                .FirstOrDefault();

            if (connectIdToRemove != 0)
            {
                _activeContexts.TryRemove(connectIdToRemove, out _);
                _lastActivity.TryRemove(connectIdToRemove, out _);

                Log.Debug("AuthenticationContextActor for connectId {ConnectId} terminated - remaining: {Remaining}", 
                    connectIdToRemove, _activeContexts.Count);
            }
        });
    }

    private void UpdateLastActivity(uint connectId)
    {
        _lastActivity.AddOrUpdate(connectId, DateTime.UtcNow, (_, _) => DateTime.UtcNow);
    }

    private int CleanupIdleActors()
    {
        DateTime now = DateTime.UtcNow;
        List<uint> toRemove = _lastActivity
            .Where(kvp => now - kvp.Value > IdleTimeout)
            .Select(kvp => kvp.Key)
            .ToList();

        int cleanedCount = 0;
        foreach (uint connectId in toRemove)
        {
            if (_activeContexts.TryRemove(connectId, out IActorRef? actor))
            {
                _lastActivity.TryRemove(connectId, out _);
                Context.Unwatch(actor);
                Context.Stop(actor);
                cleanedCount++;
            }
        }

        return cleanedCount;
    }

    private int EvictOldestIdleActors(int count)
    {
        DateTime now = DateTime.UtcNow;
        List<uint> toEvict = _lastActivity
            .OrderBy(kvp => kvp.Value) 
            .Take(count)
            .Select(kvp => kvp.Key)
            .ToList();

        int evictedCount = 0;
        foreach (uint connectId in toEvict)
        {
            if (_activeContexts.TryRemove(connectId, out IActorRef? actor))
            {
                _lastActivity.TryRemove(connectId, out _);
                Context.Unwatch(actor);
                Context.Stop(actor);
                evictedCount++;

                Log.Debug("Evicted AuthenticationContextActor for connectId {ConnectId} (idle for {IdleTime})", 
                    connectId, now - _lastActivity.GetValueOrDefault(connectId));
            }
        }

        return evictedCount;
    }

    private long EstimateMemoryUsageMb()
    {
        return _activeContexts.Count / 1024;
    }

    private int CheckForExpiredContexts()
    {
        int expiredCount = 0;
        List<uint> expiredConnections = new();

        foreach (KeyValuePair<uint, IActorRef> kvp in _activeContexts.ToList())
        {
            try
            {
                ContextInfo contextInfo = kvp.Value.Ask<ContextInfo>(new GetContextInfo(), TimeoutConfiguration.Actor.AskTimeout).Result;

                if (contextInfo is ContextInfo.Expired or ContextInfo.NotEstablished)
                {
                    expiredConnections.Add(kvp.Key);
                    expiredCount++;
                }
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "Failed to check context status for connectId {ConnectId}, marking for removal", kvp.Key);
                expiredConnections.Add(kvp.Key);
                expiredCount++;
            }
        }

        foreach (uint connectId in expiredConnections)
        {
            if (_activeContexts.TryRemove(connectId, out IActorRef? actor))
            {
                _lastActivity.TryRemove(connectId, out _);
                Context.Unwatch(actor);
                Context.Stop(actor);
            }
        }

        return expiredCount;
    }

    private static string MaskMobileNumber(string mobileNumber)
    {
        if (string.IsNullOrEmpty(mobileNumber) || mobileNumber.Length < 4)
            return "***";

        return $"{mobileNumber[..3]}****{mobileNumber[^2..]}";
    }

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return new OneForOneStrategy(
            maxNrOfRetries: 3,
            withinTimeRange: TimeSpan.FromMinutes(1),
            decider: Decider.From(ex =>
            {
                Log.Warning(ex, "AuthenticationContextActor failed - restarting");
                return Directive.Restart;
            })
        );
    }
}

internal record CleanupIdleContexts;
internal record LogMetrics;