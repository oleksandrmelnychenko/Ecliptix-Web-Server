using Akka.Actor;
using Ecliptix.DeviceProvisioning.Domain.Events;
using Ecliptix.DeviceProvisioning.Domain.Failures;
using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.IdentityAccess.Domain.Services.Security;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.Device;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.Security.Certificate.Pinning.Failures;
using Ecliptix.Security.Certificate.Pinning.Services;
using Ecliptix.Security.Opaque.Contracts;
using Ecliptix.Security.Opaque.Failures;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Actors;
using Ecliptix.SharedKernel.Configuration;
using Ecliptix.SharedKernel.Grpc;
using Ecliptix.SharedKernel.Grpc.Utilities;
using Ecliptix.SharedKernel.Grpc.Utilities.CipherPayloadHandler;
using Ecliptix.DeviceProvisioning.Infrastructure.Crypto;
using Ecliptix.DeviceProvisioning.Infrastructure.SecureChannel;
using Google.Protobuf;
using Grpc.Core;
using Microsoft.Extensions.Options;
using System.Buffers;
using System.IO;
using System.Security.Cryptography;

namespace Ecliptix.DeviceProvisioning.Infrastructure.Grpc;

public sealed class DeviceService(
    IGrpcCipherService cipherService,
    IEcliptixActorRegistry actorRegistry,
    ISecureChannelEstablisher secureChannelEstablisher,
    IOpaqueKeyRingService opaqueService,
    IMasterKeyService masterKeyService,
    IRsaChunkProcessor rsaChunkProcessor,
    CertificatePinningService certificatePinningService,
    IOptions<SecurityConfiguration> securityConfig)
    : Protobuf.Device.DeviceService.DeviceServiceBase
{
    private readonly GrpcSecurityService _baseService = new(cipherService, securityConfig);
    private readonly IActorRef _protocolActor = actorRegistry.Get(ActorIds.EcliptixProtocolSystemActor);
    private readonly IActorRef _appDevicePersistorActor = actorRegistry.Get(ActorIds.AppDevicePersistorActor);

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
                        opaqueService.GetServerPublicKey();

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

        Result<SecureEnvelope, SecureChannelFailure> result = await secureChannelEstablisher.EstablishAsync(
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
                return new RestoreChannelResponse { Status = RestoreChannelResponse.Types.Status.SessionNotFound, };
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
            return new RestoreChannelResponse { Status = RestoreChannelResponse.Types.Status.SessionNotFound };
        }

        throw GrpcFailureException.FromDomainFailure(failure);
    }

    public override async Task<SecureEnvelope> AuthenticatedEstablishSecureChannel(
        AuthenticatedEstablishRequest request, ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);
        byte[]? rootKey = null;
        byte[]? masterKeyFingerprint = null;
        byte[]? serverExchangeBuffer = null;
        int serverExchangeSize = 0;
        byte[]? encryptedPayload = null;
        byte[]? signature = null;

        try
        {
            Guid membershipId = Helpers.FromByteStringToGuid(request.MembershipUniqueId);
            if (request.AccountUniqueId.IsEmpty)
            {
                throw GrpcFailureException.FromDomainFailure(
                    MasterKeyFailure.InvalidIdentifier("AccountId is required for authenticated channel setup"));
            }

            Guid accountId = Helpers.FromByteStringToGuid(request.AccountUniqueId);

            Result<(byte[] RootKey, byte[] MasterKeyFingerprint), FailureBase> deriveRootResult =
                await masterKeyService.DeriveRootKeyAndFingerprintAsync(accountId);

            if (deriveRootResult.IsErr)
            {
                FailureBase failure = deriveRootResult.UnwrapErr();
                throw GrpcFailureException.FromDomainFailure(failure);
            }

            (rootKey, masterKeyFingerprint) = deriveRootResult.Unwrap();

            byte[] requestFingerprint = request.MasterKeyFingerprint.ToByteArray();
            if (requestFingerprint.Length != masterKeyFingerprint.Length ||
                !CryptographicOperations.FixedTimeEquals(requestFingerprint, masterKeyFingerprint))
            {
                throw GrpcFailureException.FromDomainFailure(MasterKeyFailure.MasterKeyMismatch());
            }

            InitializeProtocolWithMasterKeyActorEvent initEvent = new(
                connectId,
                request.ClientPubKeyExchange,
                membershipId,
                accountId,
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
                throw GrpcFailureException.FromDomainFailure(failure);
            }

            InitializeProtocolWithMasterKeyReply reply = initResult.Unwrap();

            ReadOnlyMemory<byte> serverExchangeMemory = ReadOnlyMemory<byte>.Empty;
            serverExchangeSize = reply.ServerPubKeyExchange.CalculateSize();
            if (serverExchangeSize > 0)
            {
                serverExchangeBuffer = ArrayPool<byte>.Shared.Rent(serverExchangeSize);
                using MemoryStream stream = new(serverExchangeBuffer, 0, serverExchangeSize, writable: true,
                    publiclyVisible: true);
                using CodedOutputStream output = new(stream, leaveOpen: true);
                reply.ServerPubKeyExchange.WriteTo(output);
                output.Flush();
                serverExchangeMemory = new ReadOnlyMemory<byte>(serverExchangeBuffer, 0, serverExchangeSize);
            }

            Result<byte[], CertificatePinningFailure> encryptResult =
                await rsaChunkProcessor.EncryptChunkedAsync(serverExchangeMemory, context.CancellationToken);

            if (encryptResult.IsErr)
            {
                CertificatePinningFailure encryptFailure = encryptResult.UnwrapErr();
                throw GrpcFailureException.FromDomainFailure(
                    SecureChannelFailure.FromCertificateFailure(encryptFailure));
            }

            encryptedPayload = encryptResult.Unwrap();

            Result<byte[], CertificatePinningFailure> signResult =
                certificatePinningService.Sign(encryptedPayload.AsMemory());

            if (signResult.IsErr)
            {
                CertificatePinningFailure signFailure = signResult.UnwrapErr();
                throw GrpcFailureException.FromDomainFailure(
                    SecureChannelFailure.FromCertificateFailure(signFailure));
            }

            signature = signResult.Unwrap();

            SecureEnvelope envelope = new()
            {
                EncryptedPayload = ByteString.CopyFrom(encryptedPayload),
                AuthenticationTag = ByteString.CopyFrom(signature),
                MetaData = ByteString.Empty,
                ResultCode = ByteString.Empty
            };

            return envelope;
        }
        catch (OperationCanceledException) when (context.CancellationToken.IsCancellationRequested)
        {
            throw;
        }
        finally
        {
            if (rootKey != null)
            {
                CryptographicOperations.ZeroMemory(rootKey);
            }

            if (masterKeyFingerprint != null)
            {
                CryptographicOperations.ZeroMemory(masterKeyFingerprint);
            }

            if (serverExchangeBuffer != null)
            {
                ArrayPool<byte>.Shared.Return(serverExchangeBuffer, clearArray: true);
            }
        }
    }
}
