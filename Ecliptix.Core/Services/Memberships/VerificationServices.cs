using System.Threading.Channels;
using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Protocol.Actors;
using Ecliptix.Core.Services.Utilities;
using Ecliptix.Domain.Memberships;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using Ecliptix.Protobuf.Verification;
using Google.Protobuf;
using Grpc.Core;
using TimerTick = Ecliptix.Protobuf.Verification.TimerTick;

namespace Ecliptix.Core.Services.Memberships;

public sealed class VerificationServices(
    IActorRegistry actorRegistry,
    ILogger<VerificationServices> logger) :
    VerificationServiceBase(actorRegistry, logger)
{
    public override async Task GetVerificationSessionIfExist(CipherPayload request,
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

        MembershipVerificationRequest
            membershipVerificationRequest = Helpers.ParseFromBytes<MembershipVerificationRequest>(
                decryptResult.Unwrap());

        Channel<TimerTick> channel = Channel.CreateUnbounded<TimerTick>();
        ChannelWriter<TimerTick> writer = channel.Writer;

        Task streamingTask = Task.Run(async () =>
        {
            await foreach (TimerTick timerTick in channel.Reader.ReadAllAsync(context.CancellationToken))
            {
                Result<CipherPayload, ShieldFailure> encryptResult = await ProtocolActor
                    .Ask<Result<CipherPayload, ShieldFailure>>(
                        new EncryptCipherPayloadCommand(
                            connectId,
                            PubKeyExchangeType.DataCenterEphemeralConnect,
                            timerTick.ToByteArray()
                        ),
                        context.CancellationToken
                    );

                if (encryptResult.IsOk)
                {
                    await responseStream.WriteAsync(encryptResult.Unwrap());
                }
            }
        });

        Result<bool, ShieldFailure> sessionResult =
            await VerificationSessionManagerActor
                .Ask<Result<bool, ShieldFailure>>(new StartVerificationSessionStreamCommand(
                    connectId,
                    membershipVerificationRequest.Mobile,
                    Helpers.FromByteStringToGuid(membershipVerificationRequest.UniqueAppDeviceRec),
                    writer
                ));

        if (sessionResult.IsOk) await streamingTask;
    }

    public override Task<CipherPayload> VerifyWithCode(CipherPayload request, ServerCallContext context)
    {
        return base.VerifyWithCode(request, context);
    }

    public override async Task SendVerificationCode(CipherPayload request, IServerStreamWriter<CipherPayload> responseStream,
        ServerCallContext context)
    {
        Result<byte[], ShieldFailure> decryptResult = await DecryptRequest(request, context);
        if (decryptResult.IsErr)
        {
            context.Status = ShieldFailure.ToGrpcStatus(decryptResult.UnwrapErr());
            await responseStream.WriteAsync(new CipherPayload());
            return;
        }
        
        uint connectId = ServiceUtilities.ExtractConnectId(context);
        
        VerifyCodeRequest verifyCodeRequest = Helpers.ParseFromBytes<VerifyCodeRequest>(
            decryptResult.Unwrap());

        VerifyCodeCommand verifyCodeCommand = new(connectId, verifyCodeRequest.Code, verifyCodeRequest.VerificationType);

        await VerificationSessionManagerActor.Ask<Result<bool,ShieldFailure>>(verifyCodeCommand);

    }
}