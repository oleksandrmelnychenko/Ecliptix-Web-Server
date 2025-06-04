using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Protocol.Actors;
using Ecliptix.Core.Services.Utilities;
using Ecliptix.Domain.Memberships;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using Grpc.Core;

namespace Ecliptix.Core.Services.Memberships;

public abstract class MembershipServicesBase(
    IActorRegistry actorRegistry,
    ILogger<MembershipServices> logger) : Ecliptix.Protobuf.Membership.MembershipServices.MembershipServicesBase
{
    protected readonly ILogger<MembershipServices> Logger = logger;

    protected readonly IActorRef MembershipActor = actorRegistry.Get<MembershipActor>();

    protected readonly IActorRef PhoneNumberValidatorActor = actorRegistry.Get<PhoneNumberValidatorActor>();

    private readonly IActorRef _protocolActor = actorRegistry.Get<EcliptixProtocolSystemActor>();

    protected async Task<Result<byte[], EcliptixProtocolFailure>> DecryptRequest(CipherPayload request, ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        Result<byte[], EcliptixProtocolFailure> decryptResult = await _protocolActor
            .Ask<Result<byte[], EcliptixProtocolFailure>>(
                new DecryptCipherPayloadActorCommand(
                    connectId,
                    PubKeyExchangeType.DataCenterEphemeralConnect,
                    request
                ),
                context.CancellationToken
            );

        return decryptResult;
    }

    private async Task<Result<CipherPayload, EcliptixProtocolFailure>> EncryptRequest(byte[] payload,
        PubKeyExchangeType pubKeyExchangeType, ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        Result<CipherPayload, EcliptixProtocolFailure> encryptResult = await _protocolActor
            .Ask<Result<CipherPayload, EcliptixProtocolFailure>>(
                new EncryptPayloadActorCommand(
                    connectId,
                    pubKeyExchangeType,
                    payload
                ),
                context.CancellationToken
            );

        return encryptResult;
    }

    protected async Task<CipherPayload> EncryptAndReturnResponse(byte[] data, ServerCallContext context)
    {
        Result<CipherPayload, EcliptixProtocolFailure> encryptResult =
            await EncryptRequest(data, PubKeyExchangeType.DataCenterEphemeralConnect, context);
        if (encryptResult.IsOk)
        {
            return encryptResult.Unwrap();
        }

        HandleError(encryptResult.UnwrapErr(), context);
        return new CipherPayload();
    }

    protected void HandleError(EcliptixProtocolFailure failure, ServerCallContext context)
    {
        context.Status = EcliptixProtocolFailure.ToGrpcStatus(failure);
        Logger.LogWarning("Error occurred: {Failure}", failure);
    }
}