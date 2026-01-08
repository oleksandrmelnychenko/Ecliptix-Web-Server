using System.Runtime.CompilerServices;
using System.Globalization;
using Ecliptix.Protobuf.Common;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Configuration;
using Ecliptix.SharedKernel.Grpc.Utilities;
using Ecliptix.SharedKernel.Grpc.Utilities.CipherPayloadHandler;
using Google.Protobuf;
using Grpc.Core;
using Microsoft.Extensions.Options;
using Serilog;

namespace Ecliptix.SharedKernel.Grpc;

public class GrpcSecurityService
{
    private readonly IGrpcCipherService _cipherService;
    private readonly SecurityConfiguration _securityConfig;

    public GrpcSecurityService(IGrpcCipherService cipherService)
    {
        _cipherService = cipherService;
        _securityConfig = new SecurityConfiguration();
    }

    public GrpcSecurityService(IGrpcCipherService cipherService, IOptions<SecurityConfiguration> securityConfig)
    {
        _cipherService = cipherService;
        _securityConfig = securityConfig.Value;
    }

    public async Task<SecureEnvelope> ExecuteEncryptedOperationAsync<TRequest, TResponse>(
        SecureEnvelope encryptedRequest,
        ServerCallContext context,
        Func<TRequest, uint, Option<string>, CancellationToken, Task<Result<TResponse, FailureBase>>> handler,
        [CallerMemberName] string operationName = "")
        where TRequest : class, IMessage<TRequest>, new()
        where TResponse : class, IMessage<TResponse>, new()
    {
        uint connectId = ExtractConnectionId(context);
        ValidateConnectionId(connectId);

        Option<string> idempotencyKey = ExtractIdempotencyKey(context);

        Result<Unit, FailureBase> timestampValidation = ValidateTimestamp(encryptedRequest, connectId);
        if (timestampValidation.IsErr)
        {
            return await CreateFailureResponseAsync<TResponse>(timestampValidation.UnwrapErr(), connectId, context);
        }

        Result<TRequest, FailureBase> decryptResult =
            await DecryptRequestAsync<TRequest>(encryptedRequest, connectId, context);
        if (decryptResult.IsErr)
        {
            SecureEnvelope failure =
                await CreateFailureResponseAsync<TResponse>(decryptResult.UnwrapErr(), connectId, context);
            return failure;
        }

        Result<TResponse, FailureBase> handlerResult =
            await handler(decryptResult.Unwrap(), connectId, idempotencyKey, context.CancellationToken);
        if (handlerResult.IsErr)
        {
            return await CreateFailureResponseAsync<TResponse>(handlerResult.UnwrapErr(), connectId, context);
        }

        SecureEnvelope response = await EncryptResponseAsync(handlerResult.Unwrap(), connectId, context);
        return response;
    }

    public async Task<Result<SecureEnvelope, FailureBase>> ExecuteEncryptedStreamingOperationAsync<TRequest, TResponse>(
        SecureEnvelope encryptedRequest,
        ServerCallContext context,
        Func<TRequest, uint, Option<string>, CancellationToken, Task<Result<TResponse, FailureBase>>> handler,
        [CallerMemberName] string operationName = "")
        where TRequest : class, IMessage<TRequest>, new()
        where TResponse : class, IMessage<TResponse>, new()
    {
        uint connectId = ExtractConnectionId(context);
        ValidateConnectionId(connectId);
        Option<string> idempotencyKey = ExtractIdempotencyKey(context);

        Result<Unit, FailureBase> timestampValidation = ValidateTimestamp(encryptedRequest, connectId);
        if (timestampValidation.IsErr)
        {
            SecureEnvelope failure =
                await CreateFailureResponseAsync<TResponse>(timestampValidation.UnwrapErr(), connectId, context);
            return Result<SecureEnvelope, FailureBase>.Ok(failure);
        }

        Result<TRequest, FailureBase> decryptResult =
            await DecryptRequestAsync<TRequest>(encryptedRequest, connectId, context);
        if (decryptResult.IsErr)
        {
            SecureEnvelope failure =
                await CreateFailureResponseAsync<TResponse>(decryptResult.UnwrapErr(), connectId, context);
            return Result<SecureEnvelope, FailureBase>.Ok(failure);
        }

        Result<TResponse, FailureBase> result =
            await handler(decryptResult.Unwrap(), connectId, idempotencyKey, context.CancellationToken);

        if (result.IsErr)
        {
            SecureEnvelope failure =
                await CreateFailureResponseAsync<TResponse>(result.UnwrapErr(), connectId, context);
            return Result<SecureEnvelope, FailureBase>.Ok(failure);
        }

        SecureEnvelope response = await EncryptResponseAsync(result.Unwrap(), connectId, context);
        return Result<SecureEnvelope, FailureBase>.Ok(response);
    }

    public async Task<Result<TResponse, FailureBase>> TryDecryptAsync<TResponse>(
        SecureEnvelope encryptedPayload,
        ServerCallContext context)
        where TResponse : class, IMessage<TResponse>, new()
    {
        uint connectId = ExtractConnectionId(context);

        Result<TResponse, FailureBase> decryptResult =
            await DecryptRequestAsync<TResponse>(encryptedPayload, connectId, context);
        return decryptResult;
    }

    private Option<string> ExtractIdempotencyKey(ServerCallContext context)
    {
        string? idempotencyKey = context.RequestHeaders.FirstOrDefault(x =>
            string.Equals(x.Key, MetadataConstants.Keys.IdempotencyKey, StringComparison.OrdinalIgnoreCase))?.Value;

        return string.IsNullOrWhiteSpace(idempotencyKey)
            ? Option<string>.None
            : Option<string>.Some(idempotencyKey);
    }

    private uint ExtractConnectionId(ServerCallContext context)
    {
        try
        {
            string? connectId = context.RequestHeaders
                .FirstOrDefault(h =>
                    string.Equals(h.Key, MetadataConstants.Keys.ConnectId, StringComparison.OrdinalIgnoreCase))
                ?.Value;
            return string.IsNullOrWhiteSpace(connectId)
                ? 0
                : (uint)decimal.Parse(connectId, NumberStyles.Any, CultureInfo.InvariantCulture);
        }
        catch (FormatException)
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument,
                MetadataConstants.ErrorMessages.InvalidConnectionIdFormat));
        }
    }

    private void ValidateConnectionId(uint connectId)
    {
        if (connectId == 0 || connectId > int.MaxValue)
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument,
                GrpcServiceConstants.ErrorMessages.ConnectionIdOutOfRange));
        }
    }

    private async Task<Result<TMessage, FailureBase>> DecryptRequestAsync<TMessage>(
        SecureEnvelope encryptedPayload,
        uint connectId,
        ServerCallContext context) where TMessage : class, IMessage<TMessage>, new()
    {
        Result<byte[], FailureBase> decryptedResult =
            await _cipherService.DecryptEnvelop(encryptedPayload, connectId, context);
        if (decryptedResult.IsErr)
        {
            return Result<TMessage, FailureBase>.Err(decryptedResult.UnwrapErr());
        }

        ReadOnlyMemory<byte> decryptedMemory = decryptedResult.Unwrap();

        try
        {
            TMessage? decryptedRequest = Activator.CreateInstance<TMessage>();
            decryptedRequest?.MergeFrom(decryptedMemory.Span);
            return Result<TMessage, FailureBase>.Ok(decryptedRequest!);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error during decryption in GrpcSecurityService");
            return Result<TMessage, FailureBase>.Err(
                EcliptixProtocolFailure.Generic(GrpcServiceConstants.ErrorMessages.FailedToParseDecryptedRequest, ex));
        }
    }

    private async Task<SecureEnvelope> EncryptResponseAsync<T>(T response, uint connectId, ServerCallContext context)
        where T : IMessage<T>, new()
    {
        byte[] responseBytes = response.ToByteArray();

        Result<SecureEnvelope, FailureBase> encryptionResult =
            await _cipherService.EncryptEnvelop(responseBytes, connectId, context);
        if (encryptionResult.IsErr)
        {
            FailureBase encryptionFailure = encryptionResult.UnwrapErr();
            ClientErrorInfo clientError = encryptionFailure.ToClientError();
            GrpcErrorDescriptor descriptor = encryptionFailure.ToGrpcDescriptor();
            throw new RpcException(
                descriptor.CreateStatus(clientError.MessageKey));
        }

        return encryptionResult.Unwrap();
    }

    private async Task<SecureEnvelope> CreateFailureResponseAsync<TResponse>(FailureBase failure, uint connectId,
        ServerCallContext context)
        where TResponse : class, IMessage<TResponse>, new()
    {
        SecureEnvelope failureResponse = await _cipherService.CreateFailureResponse(failure, connectId, context);
        return failureResponse;
    }

    private Result<Unit, FailureBase> ValidateTimestamp(SecureEnvelope encryptedRequest, uint connectId)
    {
        if (encryptedRequest.Timestamp.Seconds == 0 || encryptedRequest.Timestamp.Seconds == long.MinValue ||
            encryptedRequest.Timestamp.Seconds == long.MaxValue)
        {
            return Result<Unit, FailureBase>.Err(EcliptixProtocolFailure.Generic("Timestamp is out of range"));
        }

        DateTime requestTime = encryptedRequest.Timestamp.ToDateTime().ToUniversalTime();
        DateTime currentUtc = DateTime.UtcNow;
        DateTime earliestAllowed = currentUtc.AddSeconds(-_securityConfig.DecryptionRequestMarginInSeconds);
        DateTime latestAllowed = currentUtc.AddSeconds(_securityConfig.DecryptionRequestMarginInSeconds);

        return requestTime >= earliestAllowed && requestTime <= latestAllowed
            ? Result<Unit, FailureBase>.Ok(Unit.Value)
            : Result<Unit, FailureBase>.Err(EcliptixProtocolFailure.Generic(
                $"Request timestamp is out of range for connect ID {connectId}. Current time: {currentUtc}, request time: {requestTime}"));
    }
}
