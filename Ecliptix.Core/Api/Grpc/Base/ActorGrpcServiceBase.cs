using System.Diagnostics;
using System.Text;
using Akka.Actor;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;
using Ecliptix.Core.Observability;
using Ecliptix.Domain.Utilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.ObjectPool;

namespace Ecliptix.Core.Api.Grpc.Base;

/// <summary>
/// Base class for gRPC services that communicate with the actor system.
/// Provides optimized actor communication patterns with timeouts and circuit breaking.
/// </summary>
/// <typeparam name="TActor">The primary actor type this service communicates with</typeparam>
public abstract class ActorGrpcServiceBase<TActor> : SecuredGrpcServiceBase
    where TActor : class
{
    protected readonly IActorRef PrimaryActorRef;
    protected readonly IEcliptixActorRegistry ActorRegistry;
    
    // Default timeout for actor communications
    private static readonly TimeSpan DefaultActorTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan CriticalActorTimeout = TimeSpan.FromSeconds(10);

    protected ActorGrpcServiceBase(
        ILogger logger,
        ActivitySource activitySource,
        ObjectPool<StringBuilder> stringBuilderPool,
        IGrpcCipherService cipherService,
        ObjectPool<EncryptionContext> encryptionContextPool,
        IEcliptixActorRegistry actorRegistry,
        int primaryActorId)
        : base(logger, activitySource, stringBuilderPool, cipherService, encryptionContextPool)
    {
        ActorRegistry = actorRegistry ?? throw new ArgumentNullException(nameof(actorRegistry));
        PrimaryActorRef = actorRegistry.Get(primaryActorId);
    }

    /// <summary>
    /// Sends a message to an actor with telemetry and timeout handling
    /// </summary>
    protected async Task<TResponse> AskActorAsync<TMessage, TResponse>(
        IActorRef actorRef,
        TMessage message,
        CancellationToken cancellationToken = default,
        TimeSpan? timeout = null)
        where TMessage : class
        where TResponse : notnull
    {
        var effectiveTimeout = timeout ?? DefaultActorTimeout;
        using var activity = ActivitySource.StartActivity("AskActor");
        activity?.SetTag("actor.path", actorRef.Path.ToString());
        activity?.SetTag("message.type", typeof(TMessage).Name);
        activity?.SetTag("timeout_ms", effectiveTimeout.TotalMilliseconds);

        var stopwatch = Stopwatch.StartNew();
        
        try
        {
            // Combine the provided cancellation token with a timeout
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(effectiveTimeout);

            Logger.LogDebug("Sending {MessageType} to actor {ActorPath}", 
                typeof(TMessage).Name, actorRef.Path);

            var response = await actorRef.Ask<TResponse>(message, timeoutCts.Token);
            
            stopwatch.Stop();
            activity?.SetTag("success", true);
            activity?.SetTag("duration_ms", stopwatch.ElapsedMilliseconds);
            
            Logger.LogDebug("Received response from actor {ActorPath} in {Duration}ms", 
                actorRef.Path, stopwatch.ElapsedMilliseconds);
                
            return response;
        }
        catch (AskTimeoutException ex)
        {
            stopwatch.Stop();
            activity?.SetTag("success", false);
            activity?.SetTag("error.type", "timeout");
            activity?.SetTag("duration_ms", stopwatch.ElapsedMilliseconds);
            
            Logger.LogWarning("Actor {ActorPath} timed out after {Timeout}ms for message {MessageType}", 
                actorRef.Path, effectiveTimeout.TotalMilliseconds, typeof(TMessage).Name);
                
            throw new TimeoutException($"Actor {actorRef.Path} timed out", ex);
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            activity?.SetTag("success", false);
            activity?.SetTag("error.type", ex.GetType().Name);
            activity?.SetTag("duration_ms", stopwatch.ElapsedMilliseconds);
            
            Logger.LogError(ex, "Error communicating with actor {ActorPath} for message {MessageType}", 
                actorRef.Path, typeof(TMessage).Name);
            throw;
        }
    }

    /// <summary>
    /// Sends a message to the primary actor with default timeout
    /// </summary>
    protected async Task<TResponse> AskPrimaryActorAsync<TMessage, TResponse>(
        TMessage message,
        CancellationToken cancellationToken = default)
        where TMessage : class
        where TResponse : notnull
    {
        return await AskActorAsync<TMessage, TResponse>(PrimaryActorRef, message, cancellationToken);
    }

    /// <summary>
    /// Sends a critical message with shorter timeout for time-sensitive operations
    /// </summary>
    protected async Task<TResponse> AskCriticalAsync<TMessage, TResponse>(
        IActorRef actorRef,
        TMessage message,
        CancellationToken cancellationToken = default)
        where TMessage : class
        where TResponse : notnull
    {
        return await AskActorAsync<TMessage, TResponse>(actorRef, message, cancellationToken, CriticalActorTimeout);
    }

    /// <summary>
    /// Tells a message to an actor (fire-and-forget)
    /// </summary>
    protected void TellActor<TMessage>(IActorRef actorRef, TMessage message)
        where TMessage : class
    {
        using var activity = ActivitySource.StartActivity("TellActor");
        activity?.SetTag("actor.path", actorRef.Path.ToString());
        activity?.SetTag("message.type", typeof(TMessage).Name);

        Logger.LogDebug("Telling {MessageType} to actor {ActorPath}", 
            typeof(TMessage).Name, actorRef.Path);

        actorRef.Tell(message);
    }

    /// <summary>
    /// Executes an operation that involves actor communication with result handling
    /// </summary>
    protected async Task<Result<TSuccess, TFailure>> ExecuteActorOperationAsync<TSuccess, TFailure>(
        Func<Task<TSuccess>> operation,
        string operationName)
        where TFailure : FailureBase, new()
    {
        using var activity = ActivitySource.StartActivity($"ActorOperation.{operationName}");
        
        try
        {
            var result = await operation();
            activity?.SetTag("success", true);
            return Result<TSuccess, TFailure>.Ok(result);
        }
        catch (TimeoutException ex)
        {
            activity?.SetTag("success", false);
            activity?.SetTag("error.type", "timeout");
            
            Logger.LogWarning(ex, "Actor operation {OperationName} timed out", operationName);
            
            var failure = new TFailure { Message = $"Operation {operationName} timed out" };
            return Result<TSuccess, TFailure>.Err(failure);
        }
        catch (Exception ex)
        {
            activity?.SetTag("success", false);
            activity?.SetTag("error.type", ex.GetType().Name);
            
            Logger.LogError(ex, "Actor operation {OperationName} failed", operationName);
            
            var failure = new TFailure { Message = $"Operation {operationName} failed: {ex.Message}" };
            return Result<TSuccess, TFailure>.Err(failure);
        }
    }

    /// <summary>
    /// Checks if an actor is responsive (useful for health checks)
    /// </summary>
    protected async Task<bool> IsActorResponsiveAsync(IActorRef actorRef, TimeSpan? timeout = null)
    {
        try
        {
            var healthTimeout = timeout ?? TimeSpan.FromSeconds(5);
            using var cts = new CancellationTokenSource(healthTimeout);
            
            // Send a simple health check message
            await actorRef.Ask<object>(new { Type = "HealthCheck" }, cts.Token);
            return true;
        }
        catch
        {
            return false;
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            // Cleanup actor-specific resources
        }
        base.Dispose(disposing);
    }
}