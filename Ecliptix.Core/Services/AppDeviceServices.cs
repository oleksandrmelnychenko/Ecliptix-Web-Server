using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Actors.Messages;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Core.Services.Utilities;
using Ecliptix.Protobuf.PubKeyExchange;
using Grpc.Core;
using Status = Grpc.Core.Status;

namespace Ecliptix.Core.Services;

public class AppDeviceServices(IActorRegistry actorRegistry, ILogger<AppDeviceServices> logger)
    : AppDeviceServiceBase(actorRegistry, logger)
{
    public override async Task<PubKeyExchange> EstablishAppDeviceEphemeralConnect(PubKeyExchange request,
        ServerCallContext context)
    {
        Logger.LogInformation("Received EstablishAppDeviceEphemeralConnect request with type {RequestType}",
            request.OfType);

        Result<PubKeyExchange, ShieldFailure> keyExchangeResult = await Result<PubKeyExchange, ShieldFailure>.TryAsync(
            async () =>
            {
                BeginAppDeviceEphemeralConnectCommand command = new(request, ServiceUtilities.ExtractUniqueConnectId(context));
                BeginBeginAppDeviceEphemeralConnectReply? response = await ProtocolActor.Ask<BeginBeginAppDeviceEphemeralConnectReply>(
                    command,
                    TimeSpan.FromSeconds(5),
                    context.CancellationToken);

                return response.PubKeyExchange;
            },
            failure => failure,
            () => Logger.LogInformation("Cleaned up EstablishAppDeviceEphemeralConnect resources"));

        return keyExchangeResult.Match(
            success =>
            {
                Logger.LogInformation("Successfully established ephemeral connection");
                return success;
            },
            failure =>
            {
                Logger.LogError("Failed to establish ephemeral connection: {ErrorMessage}", failure.Message);
                Status status = ShieldFailure.ToGrpcStatus(failure);
                throw new RpcException(status);
            });
    }
}