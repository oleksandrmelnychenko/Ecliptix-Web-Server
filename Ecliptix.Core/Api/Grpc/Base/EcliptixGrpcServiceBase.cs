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

namespace Ecliptix.Core.Api.Grpc.Base;

public class EcliptixGrpcServiceBase(IGrpcCipherService cipherService)
{
    protected readonly IGrpcCipherService CipherService = cipherService;
    private static readonly ActivitySource ActivitySource = new("Ecliptix.GrpcServices");

    public async Task<CipherPayload> ExecuteEncryptedOperationAsync<TRequest, TResponse>(
        CipherPayload encryptedRequest,
        ServerCallContext context,
        Func<TRequest, uint, CancellationToken, Task<Result<TResponse, FailureBase>>> handler,
        [CallerMemberName] string operationName = "")
        where TRequest : class, IMessage<TRequest>, new()
        where TResponse : class, IMessage<TResponse>, new()
    {
        using Activity? activity = ActivitySource.StartActivity($"{GetType().Name}.{operationName}");
        activity?.SetTag("grpc.service", GetType().Name);
        activity?.SetTag("grpc.method", operationName);

        Stopwatch stopwatch = Stopwatch.StartNew();
        
        try
        {
            uint connectId = ExtractConnectionId(context);
            ValidateConnectionId(connectId);

            Log.Debug("Starting encrypted operation {ServiceName}.{MethodName} for ConnectId {ConnectId}", 
                GetType().Name, operationName, connectId);

            Result<TRequest, FailureBase> decryptResult = await DecryptRequestAsync<TRequest>(encryptedRequest, connectId, context);
            if (decryptResult.IsErr)
            {
                activity?.SetTag("decrypt_success", false);
                return await CreateFailureResponseAsync<TResponse>(decryptResult.UnwrapErr(), connectId, context);
            }

            Result<TResponse, FailureBase> handlerResult = await handler(decryptResult.Unwrap(), connectId, context.CancellationToken);
            if (handlerResult.IsErr)
            {
                activity?.SetTag("handler_success", false);
                return await CreateFailureResponseAsync<TResponse>(handlerResult.UnwrapErr(), connectId, context);
            }

            CipherPayload response = await EncryptResponseAsync(handlerResult.Unwrap(), connectId, context);
            
            stopwatch.Stop();
            activity?.SetTag("success", true);
            activity?.SetTag("duration_ms", stopwatch.ElapsedMilliseconds);
            
            Log.Debug("Completed encrypted operation {ServiceName}.{MethodName} in {Duration}ms", 
                GetType().Name, operationName, stopwatch.ElapsedMilliseconds);
                
            return response;
        }
        catch (RpcException)
        {
            stopwatch.Stop();
            activity?.SetTag("error", true);
            activity?.SetTag("duration_ms", stopwatch.ElapsedMilliseconds);
            throw;
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            activity?.SetTag("error", true);
            activity?.SetTag("duration_ms", stopwatch.ElapsedMilliseconds);
            
            Log.Error(ex, "Unexpected error in encrypted operation {ServiceName}.{MethodName}", GetType().Name, operationName);
            
            throw new RpcException(new GrpcStatus(StatusCode.Internal, "Internal server error occurred"));
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
        activity?.SetTag("grpc.service", GetType().Name);
        activity?.SetTag("grpc.method", operationName);
        activity?.SetTag("streaming", true);

        try
        {
            uint connectId = ExtractConnectionId(context);
            ValidateConnectionId(connectId);

            Result<TRequest, FailureBase> decryptResult = await DecryptRequestAsync<TRequest>(encryptedRequest, connectId, context);
            if (decryptResult.IsErr)
            {
                activity?.SetTag("decrypt_success", false);
                return Result<Unit, FailureBase>.Err(decryptResult.UnwrapErr());
            }

            Result<Unit, TFailure> result = await handler(decryptResult.Unwrap(), connectId, context.CancellationToken);
            activity?.SetTag("handler_success", result.IsOk);
            
            return result.Match(
                ok: Result<Unit, FailureBase>.Ok,
                err: Result<Unit, FailureBase>.Err
            );
        }
        catch (RpcException)
        {
            activity?.SetTag("error", true);
            throw; 
        }
        catch (Exception ex)
        {
            activity?.SetTag("error", true);
            
            Log.Error(ex, "Unexpected error in encrypted streaming operation {ServiceName}.{MethodName}", GetType().Name, operationName);
            
            throw new RpcException(new GrpcStatus(StatusCode.Internal, "Internal server error occurred"));
        }
    }

    private async Task<Result<TRequest, FailureBase>> DecryptRequestAsync<TRequest>(
        CipherPayload encryptedPayload,
        uint connectId,
        ServerCallContext context)
        where TRequest : class, IMessage<TRequest>, new()
    {
        using Activity? activity = ActivitySource.StartActivity("DecryptRequest");
        activity?.SetTag("connect_id", connectId);
        activity?.SetTag("payload_size", encryptedPayload.Cipher.Length);

        Result<byte[], FailureBase> decryptResult = await CipherService.DecryptPayload(encryptedPayload, connectId, context);
        
        if (decryptResult.IsErr)
        {
            activity?.SetTag("decrypt_success", false);
            return Result<TRequest, FailureBase>.Err(decryptResult.UnwrapErr());
        }

        try
        {
            byte[] decryptedBytes = decryptResult.Unwrap();
            TRequest parsedRequest = new TRequest();
            parsedRequest.MergeFrom(decryptedBytes);
            
            activity?.SetTag("decrypt_success", true);
            activity?.SetTag("decrypted_size", decryptedBytes.Length);
            
            return Result<TRequest, FailureBase>.Ok(parsedRequest);
        }
        catch (Exception ex)
        {
            activity?.SetTag("decrypt_success", false);
            Log.Error(ex, "Failed to parse decrypted request for ConnectId {ConnectId}", connectId);
            return Result<TRequest, FailureBase>.Err(EcliptixProtocolFailure.Generic("Failed to parse decrypted request", ex));
        }
    }

    private async Task<CipherPayload> EncryptResponseAsync<TResponse>(
        TResponse response,
        uint connectId,
        ServerCallContext context)
        where TResponse : class, IMessage<TResponse>
    {
        using Activity? activity = ActivitySource.StartActivity("EncryptResponse");
        activity?.SetTag("connect_id", connectId);

        byte[]? responseBytes = response.ToByteArray();
        activity?.SetTag("response_size", responseBytes.Length);

        Result<CipherPayload, FailureBase> encryptResult = await CipherService.EncryptPayload(responseBytes, connectId, context);
        
        if (encryptResult.IsErr)
        {
            activity?.SetTag("encrypt_success", false);
            Log.Error("Failed to encrypt response for ConnectId {ConnectId}: {Error}", 
                connectId, encryptResult.UnwrapErr().Message);
            return new CipherPayload();
        }

        activity?.SetTag("encrypt_success", true);
        activity?.SetTag("encrypted_size", encryptResult.Unwrap().Cipher.Length);
        
        return encryptResult.Unwrap();
    }

    private async Task<CipherPayload> CreateFailureResponseAsync<TResponse>(
        FailureBase failure,
        uint connectId,
        ServerCallContext context)
        where TResponse : class, IMessage<TResponse>, new()
    {
        using Activity? activity = ActivitySource.StartActivity("CreateFailureResponse");
        activity?.SetTag("connect_id", connectId);
        activity?.SetTag("failure_type", failure.GetType().Name);

        context.Status = failure.ToGrpcStatus();
        
        TResponse emptyResponse = new TResponse();
        return await EncryptResponseAsync(emptyResponse, connectId, context);
    }

    protected static uint ExtractConnectionId(ServerCallContext context)
    {
        return ServiceUtilities.ExtractConnectId(context);
    }

    protected static void ValidateConnectionId(uint connectId)
    {
        if (connectId is 0 or > uint.MaxValue - 1000)
        {
            throw new RpcException(new GrpcStatus(StatusCode.InvalidArgument, "Connection ID out of valid range"));
        }
    }
}