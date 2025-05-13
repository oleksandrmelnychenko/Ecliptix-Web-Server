using System.Threading.Channels;
using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Services.Utilities;
using Ecliptix.Domain.Memberships;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Authentication;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Core.Services.Memberships;

public sealed class AuthVerificationServices(
    IActorRegistry actorRegistry,
    ILogger<AuthVerificationServices> logger) :
    AuthVerificationServicesBase(actorRegistry, logger)
{
    public override async Task InitiateVerification(CipherPayload request,
        IServerStreamWriter<CipherPayload> responseStream,
        ServerCallContext context)
    {
        Result<byte[], ShieldFailure> decryptResult = await DecryptRequest(request, context);
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        if (!decryptResult.IsOk)
        {
            context.Status = ShieldFailure.ToGrpcStatus(decryptResult.UnwrapErr());
            await responseStream.WriteAsync(new CipherPayload());
        }

        InitiateVerificationRequest
            initiateVerificationRequest = Helpers.ParseFromBytes<InitiateVerificationRequest>(
                decryptResult.Unwrap());

        Channel<VerificationCountdownUpdate> channel = Channel.CreateUnbounded<VerificationCountdownUpdate>();
        ChannelWriter<VerificationCountdownUpdate> writer = channel.Writer;

        Task streamingTask = Task.Run(async () =>
        {
            await foreach (VerificationCountdownUpdate verificationCountdownUpdate in channel.Reader.ReadAllAsync(
                               context.CancellationToken))
            {
                Result<CipherPayload, ShieldFailure> encryptResult = await EncryptRequest(
                    verificationCountdownUpdate.ToByteArray(),
                    PubKeyExchangeType.DataCenterEphemeralConnect,
                    context
                );

                if (encryptResult.IsOk)
                {
                    await responseStream.WriteAsync(encryptResult.Unwrap());
                }
            }
        });

        Result<bool, ShieldFailure> sessionResult =
            await VerificationSessionManagerActor
                .Ask<Result<bool, ShieldFailure>>(new InitiateVerificationActorCommand(
                    connectId,
                    initiateVerificationRequest.PhoneNumber,
                    Helpers.FromByteStringToGuid(initiateVerificationRequest.DeviceIdentifier),
                    writer
                ));

        if (sessionResult.IsOk) await streamingTask;
    }


    public override async Task<CipherPayload> ValidatePhoneNumber(CipherPayload request, ServerCallContext context)
    {
        Result<byte[], ShieldFailure> decryptResult = await DecryptRequest(request, context);
        if (decryptResult.IsErr)
        {
            context.Status = ShieldFailure.ToGrpcStatus(decryptResult.UnwrapErr());
            return new CipherPayload();
        }

        ValidatePhoneNumberRequest validatePhoneNumberRequest = Helpers.ParseFromBytes<ValidatePhoneNumberRequest>(
            decryptResult.Unwrap());

        ValidatePhoneNumberCommand actorCommand = new(validatePhoneNumberRequest.PhoneNumber);

        Result<PhoneNumberValidationResult, ShieldFailure> validationResult =
            await PhoneNumberValidatorActor.Ask<Result<PhoneNumberValidationResult, ShieldFailure>>(actorCommand);

        if (validationResult.IsOk)
        {
            PhoneNumberValidationResult phoneNumberValidationResult = validationResult.Unwrap();
            if (phoneNumberValidationResult.IsValid)
            {
                ValidatePhoneNumberResponse validatePhoneNumberResponse =
                    new()
                    {
                        Result = VerificationResult.Succeeded
                    };

                Result<CipherPayload, ShieldFailure> encryptResult = await EncryptRequest(
                    validatePhoneNumberResponse.ToByteArray(),
                    PubKeyExchangeType.DataCenterEphemeralConnect, context);
                if (encryptResult.IsOk) return encryptResult.Unwrap();
                context.Status = ShieldFailure.ToGrpcStatus(encryptResult.UnwrapErr());
            }
            else
            {
                ValidatePhoneNumberResponse validatePhoneNumberResponse =
                    new()
                    {
                        Result = VerificationResult.InvalidPhone
                    };
                
                Result<CipherPayload, ShieldFailure> encryptResult = await EncryptRequest(
                    validatePhoneNumberResponse.ToByteArray(),
                    PubKeyExchangeType.DataCenterEphemeralConnect, context);
                if (encryptResult.IsOk) return encryptResult.Unwrap();
                context.Status = ShieldFailure.ToGrpcStatus(encryptResult.UnwrapErr());
            }

            return new CipherPayload();
        }

        context.Status = ShieldFailure.ToGrpcStatus(validationResult.UnwrapErr());
        return new CipherPayload();
    }

    public override async Task<CipherPayload> VerifyCode(CipherPayload request, ServerCallContext context)
    {
        Result<byte[], ShieldFailure> decryptResult = await DecryptRequest(request, context);
        if (decryptResult.IsErr)
        {
            context.Status = ShieldFailure.ToGrpcStatus(decryptResult.UnwrapErr());
            return new CipherPayload();
        }

        uint connectId = ServiceUtilities.ExtractConnectId(context);

        VerifyCodeRequest verifyCodeRequest = Helpers.ParseFromBytes<VerifyCodeRequest>(
            decryptResult.Unwrap());

        VerifyCodeActorCommand verifyCodeActorCommand =
            new(connectId, verifyCodeRequest.Code, verifyCodeRequest.Purpose);

        Result<VerifyCodeResponse, ShieldFailure> verificationResult =
            await VerificationSessionManagerActor
                .Ask<Result<VerifyCodeResponse, ShieldFailure>>(verifyCodeActorCommand);

        if (verificationResult.IsOk)
        {
            Result<CipherPayload, ShieldFailure> encryptResult = await EncryptRequest(
                verificationResult.Unwrap().ToByteArray(),
                PubKeyExchangeType.DataCenterEphemeralConnect, context);

            if (!encryptResult.IsOk)
            {
                context.Status = ShieldFailure.ToGrpcStatus(encryptResult.UnwrapErr());
                return new CipherPayload();
            }

            return encryptResult.Unwrap();
        }

        context.Status = ShieldFailure.ToGrpcStatus(verificationResult.UnwrapErr());
        return new CipherPayload();
    }
}