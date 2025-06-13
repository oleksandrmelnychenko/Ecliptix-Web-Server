using System.Threading.Channels;
using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Services.Utilities;
using Ecliptix.Domain.Memberships;
using Ecliptix.Domain.Memberships.Events;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.PhoneNumberValidation;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Protobuf.PubKeyExchange;
using Google.Protobuf;
using Grpc.Core;
using Status = Grpc.Core.Status;

namespace Ecliptix.Core.Services.Memberships;

public class AuthVerificationServices(IActorRegistry actorRegistry,IPhoneNumberValidator phoneNumberValidator, ILogger<AuthVerificationServices> logger)
    : AuthVerificationServicesBase(actorRegistry, logger)
{
    public override async Task InitiateVerification(CipherPayload request,
        IServerStreamWriter<CipherPayload> responseStream,
        ServerCallContext context)
    {
        Result<byte[], EcliptixProtocolFailure> decryptResult = await DecryptRequest(request, context);

        if (decryptResult.IsErr)
        {
            HandleProtocolError(decryptResult.UnwrapErr(), context);
            return;
        }

        InitiateVerificationRequest initiateRequest =
            Helpers.ParseFromBytes<InitiateVerificationRequest>(decryptResult.Unwrap());
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        Channel<Result<VerificationCountdownUpdate, VerificationFlowFailure>> channel =
            Channel.CreateUnbounded<Result<VerificationCountdownUpdate, VerificationFlowFailure>>();
        ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>> writer = channel.Writer;

        Task streamingTask = StreamCountdownUpdatesAsync(responseStream, channel.Reader, context);
        context.CancellationToken.Register(() => StopVerificationFlowActor(context, connectId));

        Result<Unit, VerificationFlowFailure> initiationResult = await VerificationFlowManagerActor
            .Ask<Result<Unit, VerificationFlowFailure>>(new InitiateVerificationFlowActorEvent(
                connectId,
                Helpers.FromByteStringToGuid(initiateRequest.PhoneNumberIdentifier),
                Helpers.FromByteStringToGuid(initiateRequest.AppDeviceIdentifier),
                initiateRequest.Purpose,
                initiateRequest.Type,
                writer
            ));

        //TimeSpan.FromSeconds(5)

        if (initiationResult.IsErr)
        {
            HandleVerificationError(initiationResult.UnwrapErr(), context);
            channel.Writer.TryComplete();
            return;
        }

        await streamingTask;
    }

    public override async Task<CipherPayload> ValidatePhoneNumber(CipherPayload request, ServerCallContext context)
    {
        Result<byte[], EcliptixProtocolFailure> decryptResult = await DecryptRequest(request, context);
        if (decryptResult.IsErr)
        {
            HandleProtocolError(decryptResult.UnwrapErr(), context);
            return new CipherPayload();
        }

        ValidatePhoneNumberRequest validateRequest =
            Helpers.ParseFromBytes<ValidatePhoneNumberRequest>(decryptResult.Unwrap());
        
        Result<PhoneNumberValidationResult, VerificationFlowFailure> validationResult =
            phoneNumberValidator.ValidatePhoneNumber(validateRequest.PhoneNumber, PeerCulture);

        if (validationResult.IsOk)
        {
            PhoneNumberValidationResult phoneValidationResult = validationResult.Unwrap();
            if (phoneValidationResult.IsValid)
            {
                EnsurePhoneNumberActorEvent ensurePhoneNumberActorEvent =
                    new(phoneValidationResult.ParsedPhoneNumberE164!, phoneValidationResult.DetectedRegion,
                        Helpers.FromByteStringToGuid(validateRequest.AppDeviceIdentifier));

                Result<Guid, VerificationFlowFailure> ensurePhoneNumberResult = await VerificationFlowManagerActor
                    .Ask<Result<Guid, VerificationFlowFailure>>(ensurePhoneNumberActorEvent);

                if (ensurePhoneNumberResult.IsOk)
                {
                    ValidatePhoneNumberResponse validatePhoneNumberResponse = new()
                    {
                        PhoneNumberIdentifier = Helpers.GuidToByteString(ensurePhoneNumberResult.Unwrap()),
                        Result = VerificationResult.Succeeded
                    };

                    return await EncryptAndReturnResponse(validatePhoneNumberResponse.ToByteArray(), context);
                }

                VerificationFlowFailure verificationFlowFailure = ensurePhoneNumberResult.UnwrapErr();
                ValidatePhoneNumberResponse response1 = new()
                {
                    PhoneNumberIdentifier = ByteString.Empty,
                    Result = VerificationResult.InvalidPhone,
                    Message = verificationFlowFailure.Message
                };

                return await EncryptAndReturnResponse(response1.ToByteArray(), context);
            }

            ValidatePhoneNumberResponse response = new()
            {
                Result = VerificationResult.InvalidPhone,
                Message = phoneValidationResult.MessageKey
            };

            return await EncryptAndReturnResponse(response.ToByteArray(), context);
        }

        HandleVerificationError(validationResult.UnwrapErr(), context);
        return new CipherPayload();
    }

    public override async Task<CipherPayload> VerifyOtp(CipherPayload request, ServerCallContext context)
    {
        Result<byte[], EcliptixProtocolFailure> decryptResult = await DecryptRequest(request, context);
        if (decryptResult.IsErr)
        {
            HandleProtocolError(decryptResult.UnwrapErr(), context);
            return new CipherPayload();
        }

        VerifyCodeRequest verifyRequest = Helpers.ParseFromBytes<VerifyCodeRequest>(decryptResult.Unwrap());

        uint connectId = ServiceUtilities.ExtractConnectId(context);

        VerifyFlowActorEvent actorEvent = new(connectId, verifyRequest.Code);

        Result<VerifyCodeResponse, VerificationFlowFailure> verificationResult = await VerificationFlowManagerActor
            .Ask<Result<VerifyCodeResponse, VerificationFlowFailure>>(actorEvent);

        if (verificationResult.IsOk)
        {
            return await EncryptAndReturnResponse(verificationResult.Unwrap().ToByteArray(), context);
        }

        HandleVerificationError(verificationResult.UnwrapErr(), context);
        return new CipherPayload();
    }

    private async Task StreamCountdownUpdatesAsync(
        IServerStreamWriter<CipherPayload> responseStream,
        ChannelReader<Result<VerificationCountdownUpdate, VerificationFlowFailure>> reader,
        ServerCallContext context)
    {
        try
        {
            await foreach (Result<VerificationCountdownUpdate, VerificationFlowFailure> updateResult in
                           reader.ReadAllAsync(context.CancellationToken))
            {
                if (updateResult.IsOk)
                {
                    Result<CipherPayload, EcliptixProtocolFailure> encryptResult = await EncryptRequest(
                        updateResult.Unwrap().ToByteArray(),
                        PubKeyExchangeType.DataCenterEphemeralConnect,
                        context);

                    if (encryptResult.IsOk)
                    {
                        await responseStream.WriteAsync(encryptResult.Unwrap());
                    }
                    else
                    {
                        Logger.LogError("Failed to encrypt countdown update: {Error}", encryptResult.UnwrapErr());
                        break;
                    }
                }
                else
                {
                    ////TODO send with an error status
                    HandleVerificationError(updateResult.UnwrapErr(), context);
                    break;
                }
            }
        }
        catch (OperationCanceledException)
        {
            Logger.LogInformation("Streaming task was canceled because the client disconnected.");
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "An unexpected error occurred in the streaming task.");
        }
    }

    private async Task<CipherPayload> EncryptAndReturnResponse(byte[] data, ServerCallContext context)
    {
        Result<CipherPayload, EcliptixProtocolFailure> encryptResult =
            await EncryptRequest(data, PubKeyExchangeType.DataCenterEphemeralConnect, context);
        if (encryptResult.IsOk)
        {
            return encryptResult.Unwrap();
        }

        HandleProtocolError(encryptResult.UnwrapErr(), context);
        return new CipherPayload();
    }

    private void HandleProtocolError(EcliptixProtocolFailure failure, ServerCallContext context)
    {
        Logger.LogError("Protocol error: {Error}", failure);
        Status status = failure.ToGrpcStatus();
        throw new RpcException(status);
    }

    private void HandleVerificationError(VerificationFlowFailure failure, ServerCallContext context)
    {
        if (failure.IsSecurityRelated)
        {
            Logger.LogWarning("Security-related verification error: {Error}", failure.ToStructuredLog());
        }
        else if (!failure.IsUserFacing)
        {
            Logger.LogError("System verification error: {Error}", failure.ToStructuredLog());
        }
        else
        {
            Logger.LogInformation("User verification error: {Error}", failure.ToStructuredLog());
        }

        Status status = failure.ToGrpcStatus();
        throw new RpcException(status);
    }
}