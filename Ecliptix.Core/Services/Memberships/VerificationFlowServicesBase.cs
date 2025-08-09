using System.Globalization;
using Akka.Actor;
using Ecliptix.Core.Services.Utilities;
using Ecliptix.Core.Services.Utilities.CipherPayloadHandler;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.WorkerActors;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.Membership;
using Google.Protobuf;
using Grpc.Core;
using Serilog;

namespace Ecliptix.Core.Services.Memberships;

public abstract class VerificationFlowServicesBase(
    IEcliptixActorRegistry actorRegistry,
    IGrpcCipherService grpcCipherService)
    : AuthVerificationServices.AuthVerificationServicesBase
{
    protected readonly IActorRef VerificationFlowManagerActor = actorRegistry.Get<VerificationFlowManagerActor>();

    protected readonly IGrpcCipherService GrpcCipherService = grpcCipherService;
    protected string CultureName { get; private set; } = CultureInfo.CurrentCulture.Name;

    protected void StopVerificationFlowActor(ServerCallContext context, uint connectId)
    {
        try
        {
            ActorSystem actorSystem = context.GetHttpContext().RequestServices.GetRequiredService<ActorSystem>();

            string actorName = $"flow-{connectId}";
            string actorPath = $"/membership/{nameof(VerificationFlowManagerActor)}/{actorName}";

            ActorSelection? actorSelection = actorSystem.ActorSelection(actorPath);
            
            actorSelection.Tell(new PrepareForTerminationMessage());

            Log.Information(
                "Client for ConnectId {ConnectId} disconnected. Sent PoisonPill to actor selection [{ActorPath}]",
                connectId, actorPath);
        }
        catch (Exception ex)
        {
            Log.Warning(ex,
                "Failed to send stop signal to verification flow actor for ConnectId {ConnectId}",
                connectId);
        }
    }
    
    protected async Task<CipherPayload> ExecuteWithDecryption<TRequest, TResponse>(
        CipherPayload encryptedRequest,
        ServerCallContext context,
        Func<TRequest, uint, CancellationToken, Task<CipherPayload>> handler)
        where TRequest : class, IMessage<TRequest>, new()
        where TResponse : class, IMessage<TResponse>, new()
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        Result<byte[], FailureBase> decryptionResult = await GrpcCipherService.DecryptPayload(encryptedRequest, connectId, context);

        if (decryptionResult.IsErr)
        {
            return await GrpcCipherService.CreateFailureResponse(decryptionResult.UnwrapErr(), connectId, context);
        }

        byte[] decryptedBytes = decryptionResult.Unwrap();
        TRequest parsedRequest = Helpers.ParseFromBytes<TRequest>(decryptedBytes);

        return await handler(parsedRequest, connectId, context.CancellationToken);
    }
    
    protected async Task<Result<Unit, FailureBase>> ExecuteWithDecryptionForStreaming<TRequest, TFailure>(
        CipherPayload encryptedRequest,
        ServerCallContext context,
        Func<TRequest, uint, CancellationToken, Task<Result<Unit, TFailure>>> handler)
        where TRequest : class, IMessage<TRequest>, new()
        where TFailure : FailureBase
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        Result<byte[], FailureBase> decryptionResult =
            await GrpcCipherService.DecryptPayload(encryptedRequest, connectId, context);

        if (decryptionResult.IsErr)
            return Result<Unit, FailureBase>.Err(decryptionResult.UnwrapErr());

        byte[] decryptedBytes = decryptionResult.Unwrap();
        TRequest parsedRequest = Helpers.ParseFromBytes<TRequest>(decryptedBytes);

        Result<Unit, TFailure> result = await handler(parsedRequest, connectId, context.CancellationToken);
        return result.Match(
            ok: Result<Unit, FailureBase>.Ok,
            err: Result<Unit, FailureBase>.Err
        );
    }
}