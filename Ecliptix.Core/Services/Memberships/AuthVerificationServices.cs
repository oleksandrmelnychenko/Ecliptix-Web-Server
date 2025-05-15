using System.Threading.Channels;
using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Services.Utilities;
using Ecliptix.Domain.Memberships;
using Ecliptix.Domain.Persistors;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Authentication;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Core.Services.Memberships;

public sealed class AuthVerificationServices(IActorRegistry actorRegistry, ILogger<AuthVerificationServices> logger)
    : AuthVerificationServicesBase(actorRegistry, logger)
{
    private readonly ILogger<AuthVerificationServices> _logger = logger;

    public override async Task InitiateVerification(CipherPayload request,
        IServerStreamWriter<CipherPayload> responseStream,
        ServerCallContext context)
    {
        Result<byte[], ShieldFailure> decryptResult = await DecryptRequest(request, context);
        if (decryptResult.IsErr)
        {
            HandleError(decryptResult.UnwrapErr(), context);
            return;
        }

        InitiateVerificationRequest initiateRequest =
            Helpers.ParseFromBytes<InitiateVerificationRequest>(decryptResult.Unwrap());
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        Channel<VerificationCountdownUpdate> channel = Channel.CreateUnbounded<VerificationCountdownUpdate>();
        ChannelWriter<VerificationCountdownUpdate> writer = channel.Writer;

        Task streamingTask = StreamCountdownUpdatesAsync(responseStream, channel.Reader, context);

        Result<bool, ShieldFailure> sessionResult = await VerificationSessionManagerActor
            .Ask<Result<bool, ShieldFailure>>(new InitiateVerificationActorCommand(
                connectId,
                Helpers.FromByteStringToGuid(initiateRequest.PhoneNumberIdentifier),
                Helpers.FromByteStringToGuid(initiateRequest.SystemDeviceIdentifier),
                initiateRequest.Purpose,
                writer
            ));

        if (sessionResult.IsOk)
        {
            await streamingTask;
        }
        else
        {
            HandleError(sessionResult.UnwrapErr(), context);
        }
    }

    public override async Task<CipherPayload> ValidatePhoneNumber(CipherPayload request, ServerCallContext context)
    {
        Result<byte[], ShieldFailure> decryptResult = await DecryptRequest(request, context);
        if (decryptResult.IsErr)
        {
            HandleError(decryptResult.UnwrapErr(), context);
            return new CipherPayload();
        }

        ValidatePhoneNumberRequest validateRequest =
            Helpers.ParseFromBytes<ValidatePhoneNumberRequest>(decryptResult.Unwrap());
        ValidatePhoneNumberCommand actorCommand = new(validateRequest.PhoneNumber);

        Result<PhoneNumberValidationResult, ShieldFailure> validationResult = await PhoneNumberValidatorActor
            .Ask<Result<PhoneNumberValidationResult, ShieldFailure>>(actorCommand);

        if (validationResult.IsOk)
        {
            PhoneNumberValidationResult phoneValidation = validationResult.Unwrap();
            if (phoneValidation.IsValid)
            {
                uint connectId = ServiceUtilities.ExtractConnectId(context);

                EnsurePhoneNumberActorCommand ensurePhoneNumberActorCommand =
                    new(phoneValidation.ParsedPhoneNumberE164!, phoneValidation.DetectedRegion,
                        phoneValidation.NumberType, connectId);

                Result<Guid, ShieldFailure> ensurePhoneNumberResult = await VerificationSessionManagerActor
                    .Ask<Result<Guid, ShieldFailure>>(ensurePhoneNumberActorCommand);

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

        HandleError(validationResult.UnwrapErr(), context);
        return new CipherPayload();
    }

    public override async Task<CipherPayload> VerifyCode(CipherPayload request, ServerCallContext context)
    {
        Result<byte[], ShieldFailure> decryptResult = await DecryptRequest(request, context);
        if (decryptResult.IsErr)
        {
            HandleError(decryptResult.UnwrapErr(), context);
            return new CipherPayload();
        }

        VerifyCodeRequest verifyRequest = Helpers.ParseFromBytes<VerifyCodeRequest>(decryptResult.Unwrap());

        uint connectId = ServiceUtilities.ExtractConnectId(context);

        VerifyCodeActorCommand actorCommand = new(connectId, verifyRequest.Code, verifyRequest.Purpose,
            Helpers.FromByteStringToGuid(verifyRequest.SystemDeviceIdentifier));

        Result<VerifyCodeResponse, ShieldFailure> verificationResult = await VerificationSessionManagerActor
            .Ask<Result<VerifyCodeResponse, ShieldFailure>>(actorCommand);

        if (verificationResult.IsOk)
        {
            return await EncryptAndReturnResponse(verificationResult.Unwrap().ToByteArray(), context);
        }

        HandleError(verificationResult.UnwrapErr(), context);
        return new CipherPayload();
    }

    private async Task StreamCountdownUpdatesAsync(
        IServerStreamWriter<CipherPayload> responseStream,
        ChannelReader<VerificationCountdownUpdate> reader,
        ServerCallContext context)
    {
        try
        {
            await foreach (VerificationCountdownUpdate update in reader.ReadAllAsync(context.CancellationToken))
            {
                Result<CipherPayload, ShieldFailure> encryptResult = await EncryptRequest(
                    update.ToByteArray(),
                    PubKeyExchangeType.DataCenterEphemeralConnect,
                    context);

                if (encryptResult.IsOk)
                {
                    await responseStream.WriteAsync(encryptResult.Unwrap());
                }
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("Streaming cancelled.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during streaming.");
        }
    }

    private async Task<CipherPayload> EncryptAndReturnResponse(byte[] data, ServerCallContext context)
    {
        Result<CipherPayload, ShieldFailure> encryptResult =
            await EncryptRequest(data, PubKeyExchangeType.DataCenterEphemeralConnect, context);
        if (encryptResult.IsOk)
        {
            return encryptResult.Unwrap();
        }

        HandleError(encryptResult.UnwrapErr(), context);
        return new CipherPayload();
    }

    private void HandleError(ShieldFailure failure, ServerCallContext context)
    {
        context.Status = ShieldFailure.ToGrpcStatus(failure);
        _logger.LogWarning("Error occurred: {Failure}", failure);
    }
}