using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;
using Ecliptix.Core.Observability;
using Grpc.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.ObjectPool;

namespace Ecliptix.Core.Api.Grpc.Base;

/// <summary>
/// Base class for all gRPC services providing core functionality like logging, metrics, and telemetry.
/// Implements memory-optimized patterns using object pooling and buffer reuse.
/// </summary>
public abstract class GrpcServiceBase : IDisposable
{
    protected readonly ILogger Logger;
    protected readonly ActivitySource ActivitySource;
    protected readonly ArrayPool<byte> BufferPool;
    private readonly ObjectPool<StringBuilder> _stringBuilderPool;
    
    private bool _disposed;

    protected GrpcServiceBase(
        ILogger logger,
        ActivitySource activitySource,
        ObjectPool<StringBuilder> stringBuilderPool)
    {
        Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        ActivitySource = activitySource ?? throw new ArgumentNullException(nameof(activitySource));
        _stringBuilderPool = stringBuilderPool ?? throw new ArgumentNullException(nameof(stringBuilderPool));
        BufferPool = ArrayPool<byte>.Shared;
    }

    /// <summary>
    /// Executes a gRPC operation with telemetry, error handling, and resource management
    /// </summary>
    protected async Task<TResponse> ExecuteWithTelemetryAsync<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        Func<TRequest, ServerCallContext, CancellationToken, Task<TResponse>> operation,
        [CallerMemberName] string operationName = "")
        where TRequest : class
        where TResponse : class
    {
        using var activity = ActivitySource.StartActivity($"{GetType().Name}.{operationName}");
        activity?.SetTag("grpc.service", GetType().Name);
        activity?.SetTag("grpc.method", operationName);

        var stopwatch = Stopwatch.StartNew();
        
        try
        {
            Logger.LogDebug("Starting {ServiceName}.{MethodName}", GetType().Name, operationName);
            
            var response = await operation(request, context, context.CancellationToken);
            
            stopwatch.Stop();
            activity?.SetTag("grpc.status_code", "OK");
            activity?.SetTag("duration_ms", stopwatch.ElapsedMilliseconds);
            
            Logger.LogDebug("Completed {ServiceName}.{MethodName} in {Duration}ms", 
                GetType().Name, operationName, stopwatch.ElapsedMilliseconds);
                
            return response;
        }
        catch (RpcException rpcEx)
        {
            stopwatch.Stop();
            activity?.SetTag("grpc.status_code", rpcEx.StatusCode.ToString());
            activity?.SetTag("error", true);
            activity?.SetTag("duration_ms", stopwatch.ElapsedMilliseconds);
            
            Logger.LogWarning(rpcEx, "gRPC error in {ServiceName}.{MethodName}: {StatusCode} - {Message}", 
                GetType().Name, operationName, rpcEx.StatusCode, rpcEx.Message);
            throw;
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            activity?.SetTag("grpc.status_code", "INTERNAL");
            activity?.SetTag("error", true);
            activity?.SetTag("duration_ms", stopwatch.ElapsedMilliseconds);
            
            Logger.LogError(ex, "Unexpected error in {ServiceName}.{MethodName}", GetType().Name, operationName);
            throw new RpcException(new Status(StatusCode.Internal, "Internal server error"));
        }
    }

    /// <summary>
    /// Gets a pooled StringBuilder for efficient string building operations
    /// </summary>
    protected IDisposable GetPooledStringBuilder(out StringBuilder stringBuilder)
    {
        stringBuilder = _stringBuilderPool.Get();
        return new PooledStringBuilderScope(_stringBuilderPool, stringBuilder);
    }

    /// <summary>
    /// Rents a buffer from the array pool
    /// </summary>
    protected byte[] RentBuffer(int minimumLength)
    {
        return BufferPool.Rent(minimumLength);
    }

    /// <summary>
    /// Returns a rented buffer to the pool
    /// </summary>
    protected void ReturnBuffer(byte[] buffer, bool clearBuffer = false)
    {
        BufferPool.Return(buffer, clearBuffer);
    }

    /// <summary>
    /// Extracts connection ID from gRPC context with optimized parsing
    /// </summary>
    protected static uint ExtractConnectionId(ServerCallContext context)
    {
        var connectIdHeader = context.RequestHeaders
            .FirstOrDefault(h => string.Equals(h.Key, "x-connect-id", StringComparison.OrdinalIgnoreCase));

        if (connectIdHeader?.Value == null || !uint.TryParse(connectIdHeader.Value, out var connectId))
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Missing or invalid connection ID"));
        }

        return connectId;
    }

    /// <summary>
    /// Validates that the connection ID is within acceptable bounds
    /// </summary>
    protected static void ValidateConnectionId(uint connectId)
    {
        if (connectId == 0 || connectId > uint.MaxValue - 1000)
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Connection ID out of valid range"));
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            Dispose(true);
            GC.SuppressFinalize(this);
            _disposed = true;
        }
    }

    protected virtual void Dispose(bool disposing)
    {
        // Derived classes can override this for cleanup
    }

    private sealed class PooledStringBuilderScope : IDisposable
    {
        private readonly ObjectPool<StringBuilder> _pool;
        private readonly StringBuilder _stringBuilder;

        public PooledStringBuilderScope(ObjectPool<StringBuilder> pool, StringBuilder stringBuilder)
        {
            _pool = pool;
            _stringBuilder = stringBuilder;
        }

        public void Dispose()
        {
            _stringBuilder.Clear();
            _pool.Return(_stringBuilder);
        }
    }
}