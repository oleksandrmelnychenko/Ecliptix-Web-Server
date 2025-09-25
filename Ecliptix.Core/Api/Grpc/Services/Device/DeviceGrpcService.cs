using Akka.Actor;
using Ecliptix.Core.Api.Grpc.Base;
using Ecliptix.Core.Domain.Actors;
using Ecliptix.Core.Domain.Events;
using Ecliptix.Core.Domain.Protocol.Utilities;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.SecureEnvelopeHandler;
using Ecliptix.Domain.AppDevices.Events;
using Ecliptix.Domain.AppDevices.Failures;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Device;
using Ecliptix.Protobuf.Protocol;
using Google.Protobuf;
using Grpc.Core;
using GrpcStatus = Grpc.Core.Status;
using GrpcStatusCode = Grpc.Core.StatusCode;
using Serilog;
using Ecliptix.Core.Api.Grpc;
using Ecliptix.Security.Certificate.Pinning.Failures;
using Ecliptix.Security.Certificate.Pinning.Services;

namespace Ecliptix.Core.Api.Grpc.Services.Device;

public class DeviceGrpcService(
    IGrpcCipherService cipherService,
    IEcliptixActorRegistry actorRegistry,
    ServerSecurityService serverSecurityService)
    : DeviceService.DeviceServiceBase
{
    private readonly EcliptixGrpcServiceBase _baseService = new(cipherService);
    private readonly IActorRef _protocolActor = actorRegistry.Get(ActorIds.EcliptixProtocolSystemActor);
    private readonly IActorRef _appDevicePersistorActor = actorRegistry.Get(ActorIds.AppDevicePersistorActor);

    public override async Task<SecureEnvelope> RegisterDevice(SecureEnvelope request, ServerCallContext context)
    {
        return await _baseService.ExecuteEncryptedOperationAsync<AppDevice, AppDeviceRegisteredStateReply>(
            request, context, async (appDevice, _, cancellationToken) =>
            {
                RegisterAppDeviceIfNotExistActorEvent registerEvent = new(appDevice);
                Result<AppDeviceRegisteredStateReply, AppDeviceFailure> registerResult =
                    await _appDevicePersistorActor.Ask<Result<AppDeviceRegisteredStateReply, AppDeviceFailure>>(
                        registerEvent, cancellationToken);

                return registerResult.Match(
                    response => Result<AppDeviceRegisteredStateReply, FailureBase>.Ok(response),
                    failure => Result<AppDeviceRegisteredStateReply, FailureBase>.Err(failure)
                );
            });
    }

    public override async Task<SecureEnvelope> EstablishSecureChannel(SecureEnvelope request, ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        byte[] combinedEncryptedData = request.EncryptedPayload.ToByteArray();
        const int rsaEncryptedChunkSize = 256; 

        List<byte> decryptedData = [];

        for (int offset = 0; offset < combinedEncryptedData.Length; offset += rsaEncryptedChunkSize)
        {
            int chunkSize = Math.Min(rsaEncryptedChunkSize, combinedEncryptedData.Length - offset);

            byte[] encryptedChunk = new byte[chunkSize];
            Array.Copy(combinedEncryptedData, offset, encryptedChunk, 0, chunkSize);

            Result<byte[], ServerSecurityFailure> chunkDecryptResult =
                await serverSecurityService.DecryptAsync(encryptedChunk);

            if (chunkDecryptResult.IsErr)
            {
                throw new RpcException(new GrpcStatus(GrpcStatusCode.InvalidArgument,
                    $"Failed to decrypt chunk {(offset / rsaEncryptedChunkSize) + 1}"));
            }

            decryptedData.AddRange(chunkDecryptResult.Unwrap());
        }

        PubKeyExchange pubKeyExchange = PubKeyExchange.Parser.ParseFrom(decryptedData.ToArray());

        BeginAppDeviceEphemeralConnectActorEvent actorEvent = new(pubKeyExchange, connectId);

        Result<DeriveSharedSecretReply, EcliptixProtocolFailure> reply =
            await _protocolActor.Ask<Result<DeriveSharedSecretReply, EcliptixProtocolFailure>>(
                actorEvent, context.CancellationToken);

        if (reply.IsErr)
        {
            EcliptixProtocolFailure failure = reply.UnwrapErr();
            throw new RpcException(failure.ToGrpcStatus());
        }

        PubKeyExchange responsePubKeyExchange = reply.Unwrap().PubKeyExchange;

        byte[] responseData = responsePubKeyExchange.ToByteArray();
        const int rsaMaxChunkSize = 120; 

        List<byte[]> encryptedResponseChunks = [];

        for (int offset = 0; offset < responseData.Length; offset += rsaMaxChunkSize)
        {
            int chunkSize = Math.Min(rsaMaxChunkSize, responseData.Length - offset);
            byte[] responseChunk = new byte[chunkSize];
            Array.Copy(responseData, offset, responseChunk, 0, chunkSize);

            Result<byte[], ServerSecurityFailure> chunkEncryptResult =
                await serverSecurityService.EncryptAsync(responseChunk);

            if (chunkEncryptResult.IsErr)
            {
                throw new RpcException(new GrpcStatus(GrpcStatusCode.Internal,
                    $"Failed to encrypt response chunk {(offset / rsaMaxChunkSize) + 1}"));
            }

            encryptedResponseChunks.Add(chunkEncryptResult.Unwrap());
        }

        int totalResponseSize = encryptedResponseChunks.Sum(chunk => chunk.Length);
        byte[] combinedEncryptedResponse = new byte[totalResponseSize];
        int currentResponseOffset = 0;

        foreach (byte[] chunk in encryptedResponseChunks)
        {
            Array.Copy(chunk, 0, combinedEncryptedResponse, currentResponseOffset, chunk.Length);
            currentResponseOffset += chunk.Length;
        }

        EnvelopeMetadata responseMetadata = ProtocolMigrationHelper.CreateEnvelopeMetadata(
            requestId: connectId,
            nonce: ByteString.Empty,
            ratchetIndex: 0,
            envelopeType: EnvelopeType.Response
        );

        SecureEnvelope responseEnvelope = ProtocolMigrationHelper.CreateSecureEnvelope(
            responseMetadata,
            ByteString.CopyFrom(combinedEncryptedResponse)
        );

        return responseEnvelope;
    }

    public override async Task<RestoreChannelResponse> RestoreSecureChannel(RestoreChannelRequest request,
        ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        RestoreAppDeviceSecrecyChannelState restoreEvent = new();
        ForwardToConnectActorEvent forwardEvent = new(connectId, restoreEvent);

        Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure> result =
            await _protocolActor.Ask<Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>>(
                forwardEvent, context.CancellationToken);

        if (result.IsOk)
        {
            RestoreSecrecyChannelResponse protocolResponse = result.Unwrap();
            if (protocolResponse.Status == RestoreSecrecyChannelResponse.Types.RestoreStatus.SessionNotFound)
            {
                return new RestoreChannelResponse
                {
                    Status = RestoreChannelResponse.Types.Status.SessionNotFound,
                };
            }

            return new RestoreChannelResponse
            {
                Status = RestoreChannelResponse.Types.Status.SessionRestored,
                ReceivingChainLength = protocolResponse.ReceivingChainLength,
                SendingChainLength = protocolResponse.SendingChainLength
            };
        }

        EcliptixProtocolFailure failure = result.UnwrapErr();

        if (failure.FailureType == EcliptixProtocolFailureType.ActorRefNotFound ||
            failure.FailureType == EcliptixProtocolFailureType.StateMissing ||
            _protocolActor.IsNobody())
        {
            return new RestoreChannelResponse
            {
                Status = RestoreChannelResponse.Types.Status.SessionNotFound
            };
        }

        throw new RpcException(failure.ToGrpcStatus());
    }
}