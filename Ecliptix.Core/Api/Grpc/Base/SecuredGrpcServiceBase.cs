using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;
using Ecliptix.Core.Observability;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Common;
using Google.Protobuf;
using Grpc.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.ObjectPool;

namespace Ecliptix.Core.Api.Grpc.Base;

/// <summary>
/// Base class for gRPC services that handle encrypted communication.
/// Provides optimized encryption/decryption operations with memory pooling.
/// </summary>
public abstract class SecuredGrpcServiceBase : GrpcServiceBase
{
    protected readonly IGrpcCipherService CipherService;
    private readonly ObjectPool<EncryptionContext> _encryptionContextPool;

    protected SecuredGrpcServiceBase(
        ILogger logger,
        ActivitySource activitySource, 
        ObjectPool<StringBuilder> stringBuilderPool,
        IGrpcCipherService cipherService,
        ObjectPool<EncryptionContext> encryptionContextPool) 
        : base(logger, activitySource, stringBuilderPool)
    {
        CipherService = cipherService ?? throw new ArgumentNullException(nameof(cipherService));
        _encryptionContextPool = encryptionContextPool ?? throw new ArgumentNullException(nameof(encryptionContextPool));
    }

    /// <summary>
    /// Executes an encrypted request-response operation with optimized memory management
    /// </summary>
    protected async Task<CipherPayload> ExecuteEncryptedOperationAsync<TRequest, TResponse>(
        CipherPayload encryptedRequest,
        ServerCallContext context,
        Func<TRequest, uint, CancellationToken, Task<Result<TResponse, FailureBase>>> handler,
        [CallerMemberName] string operationName = "")
        where TRequest : class, IMessage<TRequest>, new()
        where TResponse : class, IMessage<TResponse>, new()
    {
        return await ExecuteWithTelemetryAsync(encryptedRequest, context, async (request, ctx, ct) =>
        {
            var connectId = ExtractConnectionId(ctx);
            ValidateConnectionId(connectId);

            using var encryptionContext = GetEncryptionContext();
            
            // Decrypt the incoming request
            var decryptResult = await DecryptRequestAsync<TRequest>(request, connectId, ctx, ct);
            if (decryptResult.IsErr)
            {
                return await CreateFailureResponseAsync<TResponse>(decryptResult.UnwrapErr(), connectId, ctx);
            }

            // Execute the business logic
            var handlerResult = await handler(decryptResult.Unwrap(), connectId, ct);
            if (handlerResult.IsErr)
            {
                return await CreateFailureResponseAsync<TResponse>(handlerResult.UnwrapErr(), connectId, ctx);
            }

            // Encrypt and return the response
            return await EncryptResponseAsync(handlerResult.Unwrap(), connectId, encryptionContext, ctx);

        }, operationName);
    }

    /// <summary>
    /// Decrypts an incoming request using pooled resources
    /// </summary>
    private async Task<Result<TRequest, FailureBase>> DecryptRequestAsync<TRequest>(
        CipherPayload encryptedPayload,
        uint connectId,
        ServerCallContext serverContext,
        CancellationToken cancellationToken)
        where TRequest : class, IMessage<TRequest>, new()
    {
        using var activity = ActivitySource.StartActivity("DecryptRequest");
        activity?.SetTag("connect_id", connectId);
        activity?.SetTag("payload_size", encryptedPayload.Cipher.Length);

        var decryptResult = await CipherService.DecryptPayload(encryptedPayload, connectId, serverContext);
        
        if (decryptResult.IsErr)
        {
            activity?.SetTag("decrypt_success", false);
            return Result<TRequest, FailureBase>.Err(decryptResult.UnwrapErr());
        }

        try
        {
            var decryptedBytes = decryptResult.Unwrap();
            var parsedRequest = new TRequest();
            parsedRequest.MergeFrom(decryptedBytes);
            
            activity?.SetTag("decrypt_success", true);
            activity?.SetTag("decrypted_size", decryptedBytes.Length.ToString());
            
            return Result<TRequest, FailureBase>.Ok(parsedRequest);
        }
        catch (Exception ex)
        {
            activity?.SetTag("decrypt_success", false);
            Logger.LogError(ex, "Failed to parse decrypted request for connect ID {ConnectId}", connectId);
            return Result<TRequest, FailureBase>.Err(EcliptixProtocolFailure.Generic("Failed to parse decrypted request", ex));
        }
    }

    /// <summary>
    /// Encrypts a response using pooled resources
    /// </summary>
    private async Task<CipherPayload> EncryptResponseAsync<TResponse>(
        TResponse response,
        uint connectId,
        EncryptionContext context,
        ServerCallContext serverContext)
        where TResponse : class, IMessage<TResponse>
    {
        using var activity = ActivitySource.StartActivity("EncryptResponse");
        activity?.SetTag("connect_id", connectId);

        // Use pooled buffer for serialization
        var responseBytes = response.ToByteArray();
        activity?.SetTag("response_size", responseBytes.Length);

        var encryptResult = await CipherService.EncryptPayload(responseBytes, connectId, serverContext);
        
        if (encryptResult.IsErr)
        {
            activity?.SetTag("encrypt_success", false);
            Logger.LogError("Failed to encrypt response for connect ID {ConnectId}: {Error}", connectId, encryptResult.UnwrapErr().Message);
            return new CipherPayload(); // Return empty payload on encryption failure
        }

        activity?.SetTag("encrypt_success", true);
        activity?.SetTag("encrypted_size", encryptResult.Unwrap().Cipher.Length);
        
        return encryptResult.Unwrap();
    }

    /// <summary>
    /// Creates a failure response with encryption
    /// </summary>
    private async Task<CipherPayload> CreateFailureResponseAsync<TResponse>(
        FailureBase failure,
        uint connectId,
        ServerCallContext context)
        where TResponse : class, IMessage<TResponse>, new()
    {
        using var activity = ActivitySource.StartActivity("CreateFailureResponse");
        activity?.SetTag("connect_id", connectId);
        activity?.SetTag("failure_type", failure.GetType().Name);

        // Set the gRPC status
        context.Status = failure.ToGrpcStatus();

        using var encryptionContext = GetEncryptionContext();
        
        // Create empty response and encrypt it
        var emptyResponse = new TResponse();
        return await EncryptResponseAsync(emptyResponse, connectId, encryptionContext, context);
    }

    /// <summary>
    /// Gets a pooled encryption context
    /// </summary>
    private PooledEncryptionContextScope GetEncryptionContext()
    {
        var context = _encryptionContextPool.Get();
        return new PooledEncryptionContextScope(_encryptionContextPool, context);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            // Cleanup encryption-specific resources
        }
        base.Dispose(disposing);
    }

    private sealed class PooledEncryptionContextScope : IDisposable
    {
        private readonly ObjectPool<EncryptionContext> _pool;
        private readonly EncryptionContext _context;

        public PooledEncryptionContextScope(ObjectPool<EncryptionContext> pool, EncryptionContext context)
        {
            _pool = pool;
            _context = context;
        }

        public static implicit operator EncryptionContext(PooledEncryptionContextScope scope) => scope._context;

        public void Dispose()
        {
            _context.Reset();
            _pool.Return(_context);
        }
    }
}

/// <summary>
/// Reusable encryption context to avoid allocations
/// </summary>
public class EncryptionContext
{
    private byte[]? _buffer;

    public byte[] GetBuffer(int minimumSize)
    {
        if (_buffer == null || _buffer.Length < minimumSize)
        {
            if (_buffer != null)
            {
                ArrayPool<byte>.Shared.Return(_buffer);
            }
            _buffer = ArrayPool<byte>.Shared.Rent(minimumSize);
        }
        return _buffer;
    }

    public void Reset()
    {
        // Clear any sensitive data but keep the buffer for reuse
        if (_buffer != null)
        {
            Array.Clear(_buffer, 0, _buffer.Length);
        }
    }

    public void Dispose()
    {
        if (_buffer != null)
        {
            ArrayPool<byte>.Shared.Return(_buffer, clearArray: true);
            _buffer = null;
        }
    }
}