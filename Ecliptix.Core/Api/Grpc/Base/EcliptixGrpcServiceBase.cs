using System.Diagnostics;
using System.Runtime.CompilerServices;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Common;
using Google.Protobuf;
using Grpc.Core;
using GrpcStatus = Grpc.Core.Status;
using Serilog;
using Ecliptix.Core.Infrastructure.Grpc.Constants;

namespace Ecliptix.Core.Api.Grpc.Base;

public class EcliptixGrpcServiceBase(IGrpcCipherService cipherService)
{
    private static readonly ActivitySource ActivitySource = new(GrpcServiceConstants.Activities.ServiceSource);

    public async Task<CipherPayload> ExecuteEncryptedOperationAsync<TRequest, TResponse>(
        CipherPayload encryptedRequest,
        ServerCallContext context,
        Func<TRequest, uint, CancellationToken, Task<Result<TResponse, FailureBase>>> handler,
        [CallerMemberName] string operationName = "")
        where TRequest : class, IMessage<TRequest>, new()
        where TResponse : class, IMessage<TResponse>, new()
    {
        using Activity? activity = ActivitySource.StartActivity($"{GetType().Name}.{operationName}");
        activity?.SetTag(GrpcServiceConstants.ActivityTags.GrpcService, GetType().Name);
        activity?.SetTag(GrpcServiceConstants.ActivityTags.GrpcMethod, operationName);

        Stopwatch stopwatch = Stopwatch.StartNew();

        try
        {
            uint connectId = ExtractConnectionId(context);
            ValidateConnectionId(connectId);

            Log.Debug(GrpcServiceConstants.LogMessages.StartingEncryptedOperation,
                GetType().Name, operationName, connectId);

            Result<TRequest, FailureBase> decryptResult = await DecryptRequestAsync<TRequest>(encryptedRequest, connectId, context);
            if (decryptResult.IsErr)
            {
                activity?.SetTag(GrpcServiceConstants.ActivityTags.DecryptSuccess, false);
                return await CreateFailureResponseAsync<TResponse>(decryptResult.UnwrapErr(), connectId, context);
            }

            Result<TResponse, FailureBase> handlerResult = await handler(decryptResult.Unwrap(), connectId, context.CancellationToken);
            if (handlerResult.IsErr)
            {
                activity?.SetTag(GrpcServiceConstants.ActivityTags.HandlerSuccess, false);
                return await CreateFailureResponseAsync<TResponse>(handlerResult.UnwrapErr(), connectId, context);
            }

            CipherPayload response = await EncryptResponseAsync(handlerResult.Unwrap(), connectId, context);

            stopwatch.Stop();
            activity?.SetTag(GrpcServiceConstants.ActivityTags.Success, true);
            activity?.SetTag(GrpcServiceConstants.ActivityTags.DurationMs, stopwatch.ElapsedMilliseconds);

            Log.Debug(GrpcServiceConstants.LogMessages.CompletedEncryptedOperation,
                GetType().Name, operationName, stopwatch.ElapsedMilliseconds);

            return response;
        }
        catch (RpcException)
        {
            stopwatch.Stop();
            activity?.SetTag(GrpcServiceConstants.ActivityTags.Error, true);
            activity?.SetTag(GrpcServiceConstants.ActivityTags.DurationMs, stopwatch.ElapsedMilliseconds);
            throw;
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            activity?.SetTag(GrpcServiceConstants.ActivityTags.Error, true);
            activity?.SetTag(GrpcServiceConstants.ActivityTags.DurationMs, stopwatch.ElapsedMilliseconds);

            Log.Error(ex, GrpcServiceConstants.LogMessages.UnexpectedErrorInOperation, GetType().Name, operationName);

            throw new RpcException(new GrpcStatus(StatusCode.Internal, GrpcServiceConstants.ErrorMessages.InternalServerErrorOccurred));
        }
    }

    public async Task<Result<Unit, FailureBase>> ExecuteEncryptedStreamingOperationAsync<TRequest, TFailure>(
        CipherPayload encryptedRequest,
        ServerCallContext context,
        Func<TRequest, uint, CancellationToken, Task<Result<Unit, TFailure>>> handler,
        [CallerMemberName] string operationName = "")
        where TRequest : class, IMessage<TRequest>, new()
        where TFailure : FailureBase
    {
        using Activity? activity = ActivitySource.StartActivity($"{GetType().Name}.{operationName}");
        activity?.SetTag(GrpcServiceConstants.ActivityTags.GrpcService, GetType().Name);
        activity?.SetTag(GrpcServiceConstants.ActivityTags.GrpcMethod, operationName);
        activity?.SetTag(GrpcServiceConstants.ActivityTags.Streaming, true);

        try
        {
            uint connectId = ExtractConnectionId(context);
            ValidateConnectionId(connectId);

            Result<TRequest, FailureBase> decryptResult = await DecryptRequestAsync<TRequest>(encryptedRequest, connectId, context);
            if (decryptResult.IsErr)
            {
                activity?.SetTag(GrpcServiceConstants.ActivityTags.DecryptSuccess, false);
                return Result<Unit, FailureBase>.Err(decryptResult.UnwrapErr());
            }

            Result<Unit, TFailure> result = await handler(decryptResult.Unwrap(), connectId, context.CancellationToken);
            activity?.SetTag(GrpcServiceConstants.ActivityTags.HandlerSuccess, result.IsOk);

            return result.Match(
                ok: Result<Unit, FailureBase>.Ok,
                err: Result<Unit, FailureBase>.Err
            );
        }
        catch (RpcException)
        {
            activity?.SetTag(GrpcServiceConstants.ActivityTags.Error, true);
            throw; 
        }
        catch (Exception ex)
        {
            activity?.SetTag(GrpcServiceConstants.ActivityTags.Error, true);

            Log.Error(ex, GrpcServiceConstants.LogMessages.UnexpectedErrorInStreamingOperation, GetType().Name, operationName);

            throw new RpcException(new GrpcStatus(StatusCode.Internal, GrpcServiceConstants.ErrorMessages.InternalServerErrorOccurred));
        }
    }

    private async Task<Result<TRequest, FailureBase>> DecryptRequestAsync<TRequest>(
        CipherPayload encryptedPayload,
        uint connectId,
        ServerCallContext context)
        where TRequest : class, IMessage<TRequest>, new()
    {
        using Activity? activity = ActivitySource.StartActivity(GrpcServiceConstants.Activities.DecryptRequest);
        activity?.SetTag(GrpcServiceConstants.ActivityTags.ConnectId, connectId);
        activity?.SetTag(GrpcServiceConstants.ActivityTags.PayloadSize, encryptedPayload.Cipher.Length);

        Result<byte[], FailureBase> decryptResult = await cipherService.DecryptPayload(encryptedPayload, connectId, context);

        if (decryptResult.IsErr)
        {
            activity?.SetTag(GrpcServiceConstants.ActivityTags.DecryptSuccess, false);
            return Result<TRequest, FailureBase>.Err(decryptResult.UnwrapErr());
        }

        try
        {
            byte[] decryptedBytes = decryptResult.Unwrap();
            TRequest parsedRequest = new();
            parsedRequest.MergeFrom(decryptedBytes);

            activity?.SetTag(GrpcServiceConstants.ActivityTags.DecryptSuccess, true);
            activity?.SetTag(GrpcServiceConstants.ActivityTags.DecryptedSize, decryptedBytes.Length);

            return Result<TRequest, FailureBase>.Ok(parsedRequest);
        }
        catch (Exception ex)
        {
            activity?.SetTag(GrpcServiceConstants.ActivityTags.DecryptSuccess, false);
            Log.Error(ex, GrpcServiceConstants.LogMessages.FailedToParseDecryptedRequestLog, connectId);
            return Result<TRequest, FailureBase>.Err(EcliptixProtocolFailure.Generic(GrpcServiceConstants.ErrorMessages.FailedToParseDecryptedRequest, ex));
        }
    }

    private async Task<CipherPayload> EncryptResponseAsync<TResponse>(
        TResponse response,
        uint connectId,
        ServerCallContext context)
        where TResponse : class, IMessage<TResponse>
    {
        using Activity? activity = ActivitySource.StartActivity(GrpcServiceConstants.Activities.EncryptResponse);
        activity?.SetTag(GrpcServiceConstants.ActivityTags.ConnectId, connectId);

        byte[]? responseBytes = response.ToByteArray();
        activity?.SetTag(GrpcServiceConstants.ActivityTags.ResponseSize, responseBytes.Length);

        Result<CipherPayload, FailureBase> encryptResult = await cipherService.EncryptPayload(responseBytes, connectId, context);

        if (encryptResult.IsErr)
        {
            activity?.SetTag(GrpcServiceConstants.ActivityTags.EncryptSuccess, false);
            Log.Error(GrpcServiceConstants.LogMessages.FailedToEncryptResponse,
                connectId, encryptResult.UnwrapErr().Message);
            return new CipherPayload();
        }

        activity?.SetTag(GrpcServiceConstants.ActivityTags.EncryptSuccess, true);
        activity?.SetTag(GrpcServiceConstants.ActivityTags.EncryptedSize, encryptResult.Unwrap().Cipher.Length);

        return encryptResult.Unwrap();
    }

    private async Task<CipherPayload> CreateFailureResponseAsync<TResponse>(
        FailureBase failure,
        uint connectId,
        ServerCallContext context)
        where TResponse : class, IMessage<TResponse>, new()
    {
        using Activity? activity = ActivitySource.StartActivity(GrpcServiceConstants.Activities.CreateFailureResponse);
        activity?.SetTag(GrpcServiceConstants.ActivityTags.ConnectId, connectId);
        activity?.SetTag(GrpcServiceConstants.ActivityTags.FailureType, failure.GetType().Name);

        context.Status = failure.ToGrpcStatus();

        TResponse emptyResponse = new();
        return await EncryptResponseAsync(emptyResponse, connectId, context);
    }

    private static uint ExtractConnectionId(ServerCallContext context)
    {
        return ServiceUtilities.ExtractConnectId(context);
    }

    private static void ValidateConnectionId(uint connectId)
    {
        if (connectId is 0 or > InterceptorConstants.Limits.MaxConnectId)
        {
            throw new RpcException(new GrpcStatus(StatusCode.InvalidArgument, GrpcServiceConstants.ErrorMessages.ConnectionIdOutOfRange));
        }
    }
}