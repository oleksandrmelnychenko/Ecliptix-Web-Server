using System.Security.Cryptography;
using Akka.Actor;
using Serilog;

namespace Ecliptix.Domain.Memberships.WorkerActors;

public record AuthenticationContext
{
    public byte[] ContextToken { get; init; } = Array.Empty<byte>();
    public Guid MembershipId { get; init; }
    public Guid MobileNumberId { get; init; }
    public DateTime EstablishedAt { get; init; }
    public DateTime ExpiresAt { get; init; }
    public bool IsEstablished => ContextToken.Length > 0;
}

public class AuthenticationContextActor : ReceiveActor
{
    private readonly uint _connectId;
    private readonly IActorRef _parent;
    
    private readonly Queue<DateTime> _attemptTimestamps = new();
    private AuthenticationContext? _establishedContext;
    private bool _isRateLimited;
    private DateTime? _rateLimitedUntil;
    
    private const int MaxAttemptsPerWindow = 5;
    private static readonly TimeSpan WindowSize = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan LockDuration = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan AutoCleanupTimeout = TimeSpan.FromMinutes(30);
    
    private ICancelable? _autoCleanupTimer;

    public AuthenticationContextActor(uint connectId, IActorRef parent)
    {
        _connectId = connectId;
        _parent = parent;
        
        Become(Ready);
    }

    public static Props Build(uint connectId, IActorRef parent)
    {
        return Props.Create(() => new AuthenticationContextActor(connectId, parent));
    }

    protected override void PreStart()
    {
        base.PreStart();
        
        // Set auto-cleanup timer to prevent memory leaks
        _autoCleanupTimer = Context.System.Scheduler.ScheduleTellOnceCancelable(
            AutoCleanupTimeout,
            Self,
            new AutoCleanup(),
            ActorRefs.NoSender);

        Log.Debug("AuthenticationContextActor started for connectId {ConnectId}", _connectId);
    }

    protected override void PostStop()
    {
        _autoCleanupTimer?.Cancel();
        
        Log.Debug("AuthenticationContextActor stopped for connectId {ConnectId}", _connectId);
        
        base.PostStop();
    }

    private void Ready()
    {
        Receive<AttemptAuthentication>(msg =>
        {
            ResetAutoCleanupTimer();
            
            var result = CheckRateLimit();
            Sender.Tell(result);
            
            // Log attempt for monitoring
            if (result is AuthResult.RateLimited rateLimited)
            {
                Log.Warning("Authentication rate limited for connectId {ConnectId}, mobile {MaskedMobileNumber} until {LockedUntil}", 
                    _connectId, MaskMobileNumber(msg.MobileNumber), rateLimited.LockedUntil);
            }
            else
            {
                Log.Debug("Authentication attempt allowed for connectId {ConnectId}, mobile {MaskedMobileNumber} - {AttemptsInWindow} attempts in window", 
                    _connectId, MaskMobileNumber(msg.MobileNumber), _attemptTimestamps.Count);
            }
        });

        Receive<EstablishContext>(msg =>
        {
            ResetAutoCleanupTimer();
            
            // Generate secure context token if not provided
            byte[] contextToken = msg.ContextToken;
            if (contextToken.Length == 0)
            {
                contextToken = GenerateSecureToken();
            }
            
            DateTime expiresAt = DateTime.UtcNow.AddHours(24);
            
            _establishedContext = new AuthenticationContext
            {
                ContextToken = contextToken,
                MembershipId = msg.MembershipId,
                MobileNumberId = msg.MobileNumberId,
                EstablishedAt = DateTime.UtcNow,
                ExpiresAt = expiresAt
            };
            
            // Reset rate limiting state on successful authentication
            _attemptTimestamps.Clear();
            _isRateLimited = false;
            _rateLimitedUntil = null;
            
            Log.Information("Authentication context established for connectId {ConnectId}, membershipId {MembershipId}", 
                _connectId, msg.MembershipId);
            
            Sender.Tell(new AuthContextEstablished(contextToken, expiresAt));
        });


        Receive<AutoCleanup>(_ =>
        {
            Log.Debug("Auto-cleanup triggered for idle AuthenticationContextActor - connectId {ConnectId}", _connectId);
            
            // Notify parent to remove us and stop
            _parent.Tell(new RemoveAuthContext(_connectId));
            Context.Stop(Self);
        });
    }

    private AuthResult CheckRateLimit()
    {
        CleanOldAttempts();
        
        if (_isRateLimited && _rateLimitedUntil.HasValue)
        {
            if (DateTime.UtcNow < _rateLimitedUntil.Value)
            {
                return new AuthResult.RateLimited(_rateLimitedUntil.Value);
            }
            
            _isRateLimited = false;
            _rateLimitedUntil = null;
        }
        
        if (_attemptTimestamps.Count >= MaxAttemptsPerWindow)
        {
            _isRateLimited = true;
            _rateLimitedUntil = DateTime.UtcNow.Add(LockDuration);
            
            return new AuthResult.RateLimited(_rateLimitedUntil.Value);
        }
        
        _attemptTimestamps.Enqueue(DateTime.UtcNow);
        return new AuthResult.Proceed();
    }

    private void CleanOldAttempts()
    {
        DateTime cutoffTime = DateTime.UtcNow - WindowSize;
        
        while (_attemptTimestamps.Count > 0 && _attemptTimestamps.Peek() < cutoffTime)
        {
            _attemptTimestamps.Dequeue();
        }
    }


    private void ResetAutoCleanupTimer()
    {
        _autoCleanupTimer?.Cancel();
        _autoCleanupTimer = Context.System.Scheduler.ScheduleTellOnceCancelable(
            AutoCleanupTimeout,
            Self,
            new AutoCleanup(),
            ActorRefs.NoSender);
    }

    private static byte[] GenerateSecureToken()
    {
        byte[] token = new byte[64];
        using RandomNumberGenerator rng = RandomNumberGenerator.Create();
        rng.GetBytes(token);
        
        byte[] result = new byte[64];
        token.CopyTo(result, 0);
        CryptographicOperations.ZeroMemory(token);
        
        return result;
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
            maxNrOfRetries: 2,
            withinTimeRange: TimeSpan.FromMinutes(1),
            decider: Decider.From(ex =>
            {
                Log.Error(ex, "AuthenticationContextActor error for connectId {ConnectId}", _connectId);
                return Directive.Restart;
            })
        );
    }
}

// Internal message for AuthenticationContextActor
internal record AutoCleanup;