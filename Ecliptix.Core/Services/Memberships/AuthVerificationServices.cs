using System.Threading.Channels;
using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Services.Utilities;
using Ecliptix.Domain.Memberships;
using Ecliptix.Domain.Memberships.Events;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Protobuf.PubKeyExchange;
using Google.Protobuf;
using Grpc.Core;
using Status = Grpc.Core.Status;

namespace Ecliptix.Core.Services.Memberships;

public class AuthVerificationServices(IActorRegistry actorRegistry, ILogger<AuthVerificationServices> logger)
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

        Result<bool, VerificationFlowFailure> sessionResult = await VerificationSessionManagerActor
            .Ask<Result<bool, VerificationFlowFailure>>(new InitiateVerificationFlowActorEvent(
                connectId,
                Helpers.FromByteStringToGuid(initiateRequest.PhoneNumberIdentifier),
                Helpers.FromByteStringToGuid(initiateRequest.AppDeviceIdentifier),
                initiateRequest.Purpose,
                initiateRequest.Type,
                writer
            ));

        if (sessionResult.IsOk)
        {
            await streamingTask;
        }
        else
        {
            HandleVerificationError(sessionResult.UnwrapErr(), context);
        }
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
        ValidatePhoneNumberActorEvent actorActorEvent = new(validateRequest.PhoneNumber);

        Result<PhoneNumberValidationResult, VerificationFlowFailure> validationResult = await PhoneNumberValidatorActor
            .Ask<Result<PhoneNumberValidationResult, VerificationFlowFailure>>(actorActorEvent);

        if (validationResult.IsOk)
        {
            PhoneNumberValidationResult phoneValidation = validationResult.Unwrap();
            if (phoneValidation.IsValid)
            {
                EnsurePhoneNumberActorEvent ensurePhoneNumberActorEvent =
                    new(phoneValidation.ParsedPhoneNumberE164!, phoneValidation.DetectedRegion);

                Result<Guid, VerificationFlowFailure> ensurePhoneNumberResult = await VerificationSessionManagerActor
                    .Ask<Result<Guid, VerificationFlowFailure>>(ensurePhoneNumberActorEvent);

                if (ensurePhoneNumberResult.IsOk)
                {
                    ValidatePhoneNumberResponse response = new()
                    {
                        PhoneNumberIdentifier = Helpers.GuidToByteString(ensurePhoneNumberResult.Unwrap()),
                        Result = VerificationResult.Succeeded
                    };

                    return await EncryptAndReturnResponse(response.ToByteArray(), context);
                }
            }
            else
            {
                ValidatePhoneNumberResponse response = new()
                {
                    Result = VerificationResult.InvalidPhone
                };

                return await EncryptAndReturnResponse(response.ToByteArray(), context);
            }
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

        Result<VerifyCodeResponse, VerificationFlowFailure> verificationResult = await VerificationSessionManagerActor
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
        await foreach (Result<VerificationCountdownUpdate, VerificationFlowFailure> update in reader.ReadAllAsync(
                           context.CancellationToken))
        {
            if (update.IsOk)
            {
                VerificationCountdownUpdate verificationCountdownUpdate = update.Unwrap();
                Result<CipherPayload, EcliptixProtocolFailure> encryptResult = await EncryptRequest(
                    verificationCountdownUpdate.ToByteArray(),
                    PubKeyExchangeType.DataCenterEphemeralConnect,
                    context);

                if (encryptResult.IsOk)
                {
                    await responseStream.WriteAsync(encryptResult.Unwrap());
                }
            }
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