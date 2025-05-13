using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Protocol.Actors;
using Ecliptix.Core.Services.Utilities;
using Ecliptix.Domain.Memberships;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Authentication;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using Grpc.Core;

namespace Ecliptix.Core.Services.Memberships;

public class AuthVerificationServicesBase(
    IActorRegistry actorRegistry,
    ILogger<AuthVerificationServices> logger) : AuthenticationServices.AuthenticationServicesBase
{
    protected readonly ILogger<AuthVerificationServices> Logger = logger;
   
    protected readonly IActorRef VerificationSessionManagerActor = actorRegistry.Get<VerificationSessionManagerActor>();

    protected readonly IActorRef PhoneNumberValidatorActor = actorRegistry.Get<PhoneNumberValidatorActor>();
    
    private readonly IActorRef _protocolActor = actorRegistry.Get<EcliptixProtocolSystemActor>();
    
    protected async Task<Result<byte[], ShieldFailure>> DecryptRequest(CipherPayload request, ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        Result<byte[], ShieldFailure> decryptResult = await _protocolActor
            .Ask<Result<byte[], ShieldFailure>>(
                new DecryptCipherPayloadActorCommand(
                    connectId,
                    PubKeyExchangeType.DataCenterEphemeralConnect,
                    request
                ),
                context.CancellationToken
            );

        return decryptResult;
    }

    protected async Task<Result<CipherPayload, ShieldFailure>> EncryptRequest(byte[] payload, PubKeyExchangeType pubKeyExchangeType, ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        Result<CipherPayload, ShieldFailure> encryptResult = await _protocolActor
            .Ask<Result<CipherPayload, ShieldFailure>>(
                new EncryptPayloadActorCommand(
                    connectId,
                    pubKeyExchangeType,
                    payload
                ),
                context.CancellationToken
            );

        return encryptResult;
    }
}