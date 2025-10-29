using Akka.Actor;
using Ecliptix.Core.Api.Grpc.Base;
using Ecliptix.Core.Domain.Events;
using Ecliptix.Core.Domain.Protocol;
using Ecliptix.Core.Infrastructure.Crypto;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;
using Ecliptix.Core.Infrastructure.SecureChannel;
using Ecliptix.Domain.AppDevices.Events;
using Ecliptix.Domain.AppDevices.Failures;
using Ecliptix.Domain.Services.Security;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Device;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.Security.Certificate.Pinning.Failures;
using Ecliptix.Security.Certificate.Pinning.Services;
using Ecliptix.Security.Opaque.Failures;
using Ecliptix.Security.Opaque.Services;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Configuration;
using Google.Protobuf;
using Grpc.Core;
using Microsoft.Extensions.Options;

namespace Ecliptix.Core.Api.Grpc.Services.Device;

internal sealed class DeviceService : Protobuf.Device.DeviceService.DeviceServiceBase
{
    private readonly GrpcSecurityService _baseService;
    private readonly IActorRef _protocolActor;
    private readonly IActorRef _appDevicePersistorActor;
    private readonly ISecureChannelEstablisher _secureChannelEstablisher;
    private readonly INativeOpaqueProtocolService _opaqueService;
    private readonly IMasterKeyService _masterKeyService;
    private readonly IRsaChunkProcessor _rsaChunkProcessor;
    private readonly CertificatePinningService _certificatePinningService;

    public DeviceService(
        IGrpcCipherService cipherService,
        IEcliptixActorRegistry actorRegistry,
        ISecureChannelEstablisher secureChannelEstablisher,
        INativeOpaqueProtocolService opaqueService,
        IMasterKeyService masterKeyService,
        IRsaChunkProcessor rsaChunkProcessor,
        CertificatePinningService certificatePinningService,
        IOptions<SecurityConfiguration> securityConfig)
    {
        _baseService = new GrpcSecurityService(cipherService, securityConfig);
        _protocolActor = actorRegistry.Get(ActorIds.EcliptixProtocolSystemActor);
        _appDevicePersistorActor = actorRegistry.Get(ActorIds.AppDevicePersistorActor);
        _secureChannelEstablisher = secureChannelEstablisher;
        _opaqueService = opaqueService;
        _masterKeyService = masterKeyService;
        _rsaChunkProcessor = rsaChunkProcessor;
        _certificatePinningService = certificatePinningService;
    }

    public override async Task<SecureEnvelope> RegisterDevice(SecureEnvelope request, ServerCallContext context)
    {
        return await _baseService.ExecuteEncryptedOperationAsync<AppDevice, DeviceRegistrationResponse>(
            request, context, async (appDevice, _, _, cancellationToken) =>
            {
                RegisterAppDeviceIfNotExistActorEvent registerEvent = new(appDevice, cancellationToken);
                Task<Result<DeviceRegistrationResponse, AppDeviceFailure>> registerTask =
                    _appDevicePersistorActor.Ask<Result<DeviceRegistrationResponse, AppDeviceFailure>>(
                        registerEvent,
                        TimeoutConfiguration.Actor.AskTimeout);
                Result<DeviceRegistrationResponse, AppDeviceFailure> registerResult =
                    await registerTask.WaitAsync(cancellationToken).ConfigureAwait(false);

                if (registerResult.IsOk)
                {
                    Result<byte[], OpaqueServerFailure> serverPublicKey =
                        ((OpaqueProtocolService)_opaqueService).GetServerPublicKey();

                    DeviceRegistrationResponse reply = registerResult.Unwrap();
                    reply.ServerPublicKey = ByteString.CopyFrom(serverPublicKey.Unwrap());

                    return Result<DeviceRegistrationResponse, FailureBase>.Ok(reply);
                }

                return Result<DeviceRegistrationResponse, FailureBase>.Err(registerResult.UnwrapErr());
            });
    }

    public override async Task<SecureEnvelope> EstablishSecureChannel(SecureEnvelope request, ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        Result<SecureEnvelope, SecureChannelFailure> result = await _secureChannelEstablisher.EstablishAsync(
            request,
            connectId,
            context.CancellationToken);

        return result.Match(
            success => success,
            failure => throw GrpcFailureException.FromDomainFailure(failure));
    }

    public override async Task<RestoreChannelResponse> RestoreSecureChannel(RestoreChannelRequest request,
        ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        RestoreAppDeviceSecrecyChannelState restoreEvent = new();
        ForwardToConnectActorEvent forwardEvent = new(connectId, restoreEvent);

        Task<Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>> restoreTask =
            _protocolActor.Ask<Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>>(
                forwardEvent,
                TimeoutConfiguration.Actor.AskTimeout);
        Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure> result =
            await restoreTask.WaitAsync(context.CancellationToken).ConfigureAwait(false);

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

        throw GrpcFailureException.FromDomainFailure(failure);
    }

    public override async Task<SecureEnvelope> AuthenticatedEstablishSecureChannel(
        AuthenticatedEstablishRequest request, ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);
        byte[]? rootKey = null;

        try
        {
            Guid membershipId = Helpers.FromByteStringToGuid(request.MembershipUniqueId);

            Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase> deriveKeysResult =
                await _masterKeyService.DeriveIdentityKeysAsync(membershipId);

            if (deriveKeysResult.IsErr)
            {
                FailureBase failure = deriveKeysResult.UnwrapErr();
                throw GrpcFailureException.FromDomainFailure(failure);
            }

            (dynamic identityKeysObj, byte[] rootKeyBytes) = deriveKeysResult.Unwrap();
            EcliptixSystemIdentityKeys identityKeys = (EcliptixSystemIdentityKeys)identityKeysObj;
            rootKey = rootKeyBytes;

            InitializeProtocolWithMasterKeyActorEvent initEvent = new(
                connectId,
                identityKeys,
                request.ClientPubKeyExchange,
                membershipId,
                rootKey);

            ForwardToConnectActorEvent forwardEvent = new(connectId, initEvent);

            Task<Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>> initTask =
                _protocolActor.Ask<Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>>(
                    forwardEvent,
                    TimeoutConfiguration.Actor.AskTimeout);
            Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure> initResult =
                await initTask.WaitAsync(context.CancellationToken).ConfigureAwait(false);

            if (initResult.IsErr)
            {
                EcliptixProtocolFailure failure = initResult.UnwrapErr();
                identityKeys.Dispose();
                throw GrpcFailureException.FromDomainFailure(failure);
            }

            InitializeProtocolWithMasterKeyReply reply = initResult.Unwrap();

            byte[] serverExchangeBytes = reply.ServerPubKeyExchange.ToByteArray();

            Result<byte[], CertificatePinningFailure> encryptResult =
                await _rsaChunkProcessor.EncryptChunkedAsync(serverExchangeBytes, context.CancellationToken);

            if (encryptResult.IsErr)
            {
                CertificatePinningFailure encryptFailure = encryptResult.UnwrapErr();
                throw GrpcFailureException.FromDomainFailure(
                    SecureChannelFailure.FromCertificateFailure(encryptFailure));
            }

            byte[] encryptedPayload = encryptResult.Unwrap();

            Result<byte[], CertificatePinningFailure> signResult =
                _certificatePinningService.Sign(encryptedPayload.AsMemory());

            if (signResult.IsErr)
            {
                CertificatePinningFailure signFailure = signResult.UnwrapErr();
                throw GrpcFailureException.FromDomainFailure(
                    SecureChannelFailure.FromCertificateFailure(signFailure));
            }

            byte[] signature = signResult.Unwrap();

            return new SecureEnvelope
            {
                EncryptedPayload = ByteString.CopyFrom(encryptedPayload),
                AuthenticationTag = ByteString.CopyFrom(signature),
                MetaData = ByteString.Empty,
                ResultCode = ByteString.Empty
            };
        }
        finally
        {
            if (rootKey != null)
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(rootKey);
            }
        }
    }
}
