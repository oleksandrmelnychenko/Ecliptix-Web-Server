using System.Collections.Concurrent;
using Akka.Actor;
using Ecliptix.Core.Actors.Messages;
using Ecliptix.Core.Protocol;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using Serilog.Context;

namespace Ecliptix.Core.Actors;

public class EcliptixProtocolSystemActor
    : ReceiveActor
{
    private readonly ILogger<EcliptixProtocolSystemActor> _logger;
    private readonly ConcurrentDictionary<uint, IActorRef> _sessions = new();

    private readonly EcliptixSystemIdentityKeys _ecliptixSystemIdentityKeys;
    private readonly IActorRef _ecliptixProtocolConnectionsManagerActor;

    private EcliptixProtocolSystemActor(EcliptixSystemIdentityKeys ecliptixSystemIdentityKeys,
        IActorRef ecliptixProtocolConnectionsManagerActor,
        ILogger<EcliptixProtocolSystemActor> logger)
    {
        _ecliptixSystemIdentityKeys = ecliptixSystemIdentityKeys;
        _ecliptixProtocolConnectionsManagerActor = ecliptixProtocolConnectionsManagerActor;
        _logger = logger;
        Become(Ready);
    }

    private void Ready()
    {
        ReceiveAsync<BeginAppDeviceEphemeralConnectCommand>(HandleBeginAppDeviceEphemeralConnectCommand);
        ReceiveAsync<ProcessExchangeResponseCommand>(HandleProcessExchangeResponseAsync);
        ReceiveAsync<CompleteExchangeCommand>(HandleCompleteExchangeCommandAsync);
        ReceiveAsync<SendOutboundMessageCommand>(HandleSendOutboundMessageAsync);
        ReceiveAsync<ProcessInboundMessageCommand>(HandleProcessInboundMessageAsync);
    }

    private async Task<Result<PubKeyExchange,ShieldFailure>> HandleBeginAppDeviceEphemeralConnectCommand(BeginAppDeviceEphemeralConnectCommand command)
    {
        uint connectId = command.UniqueConnectId;
        PubKeyExchangeState exchangeType = command.PubKeyExchange.State;
        
        _logger.LogInformation($"[ShieldPro] Beginning exchange {exchangeType}, generated Session ID: {connectId}");

        Result<LocalPublicKeyBundle, ShieldFailure> localBundleResult = _ecliptixSystemIdentityKeys.CreatePublicBundle();
        if (!localBundleResult.IsOk)
        {
            return Task.FromResult(Result<PubKeyExchange, ShieldFailure>(localBundleResult.UnwrapErr()));
        }
        
        LocalPublicKeyBundle localBundle = localBundleResult.Unwrap();

        PublicKeyBundle protoBundle = localBundle.ToProtobufExchange();
       
        _ecliptixSystemIdentityKeys.GenerateEphemeralKeyPair();
        
        
        _ecliptixProtocolConnectionsManagerActor.Ask<CreateConnectCommand>(connectId,PubKeyExchange)
        
        
        Result<ShieldSession, ShieldFailure> sessionResult = ShieldSession.Create(connectId, localBundle, false);
        if (!sessionResult.IsOk)
        {
            
        }
        
        ShieldSession session = sessionResult.Unwrap();
        
        try
        {
            /*PublicKeyBundle peerPublicKeyBundle =  Utilities.Utilities.ParseFromBytes<PublicKeyBundle>(
                Utilities.Utilities.ReadMemoryToRetrieveBytes(request.Payload.Memory));*/

            // Create new actor ?

            (uint sessionId, PubKeyExchange initialMessage) =
                await _ecliptixProtocolSystem.BeginDataCenterPubKeyExchangeAsync(command.ExchangeType);
            Sender.Tell(new BeginBeginAppDeviceEphemeralConnectReply(initialMessage));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in BeginDataCenterPubKeyExchangeAsync");
            Sender.Tell(new BeginExchangeFailure(ex.Message));
        }
    }

    private async Task HandleProcessExchangeResponseAsync(ProcessExchangeResponseCommand command)
    {
        using (LogContext.PushProperty("SessionId", command.SessionId))
        using (LogContext.PushProperty("ExchangeType", command.PeerInitialMessage))
        {
            _logger.LogInformation("Handling ProcessExchangeResponseCommand");
            try
            {
                (uint sessionId, PubKeyExchange responseMessage) =
                    await _ecliptixProtocolSystem.ProcessAndRespondToPubKeyExchangeAsync(command.PeerInitialMessage);
                Sender.Tell(new ProcessExchangeResponse(sessionId, responseMessage));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in ProcessAndRespondToPubKeyExchangeAsync");
                Sender.Tell(new ProcessExchangeResponseFailure(ex.Message));
            }
        }
    }

    private async Task HandleCompleteExchangeCommandAsync(CompleteExchangeCommand command)
    {
        using (LogContext.PushProperty("SessionId", command.SessionId))
        using (LogContext.PushProperty("ExchangeType", command.ExchangeType))
        {
            _logger.LogInformation("Handling CompleteExchangeCommand");
            try
            {
                (uint sessionId, SodiumSecureMemoryHandle rootKeyHandle) =
                    await _ecliptixProtocolSystem.CompleteDataCenterPubKeyExchangeAsync(
                        command.SessionId, command.ExchangeType, command.PeerMessage);
                Sender.Tell(new CompleteExchangeResponse(sessionId));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in CompleteDataCenterPubKeyExchangeAsync");
                Sender.Tell(new CompleteExchangeFailure(ex.Message));
            }
        }
    }

    private async Task HandleSendOutboundMessageAsync(SendOutboundMessageCommand command)
    {
        using (LogContext.PushProperty("SessionId", command.SessionId))
        using (LogContext.PushProperty("ExchangeType", command.ExchangeType))
        {
            _logger.LogInformation("Handling SendOutboundMessageCommand");
            try
            {
                CipherPayload cipherPayload = await _ecliptixProtocolSystem.ProduceOutboundMessageAsync(
                    command.SessionId, command.ExchangeType, command.PlainPayload);
                Sender.Tell(new SendOutboundMessageResponse(cipherPayload));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in ProduceOutboundMessageAsync");
                Sender.Tell(new SendOutboundMessageFailure(ex.Message));
            }
        }
    }

    private async Task HandleProcessInboundMessageAsync(ProcessInboundMessageCommand command)
    {
        using (LogContext.PushProperty("SessionId", command.SessionId))
        using (LogContext.PushProperty("ExchangeType", command.ExchangeType))
        {
            _logger.LogInformation("Handling ProcessInboundMessageCommand");
            try
            {
                var plaintext = await _ecliptixProtocolSystem.ProcessInboundMessageAsync(
                    command.SessionId, command.ExchangeType, command.CipherPayload);
                Sender.Tell(new ProcessInboundMessageResponse(plaintext));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in ProcessInboundMessageAsync");
                Sender.Tell(new ProcessInboundMessageFailure(ex.Message));
            }
        }
    }
    
    public async Task<(uint SessionId, PubKeyExchange InitialMessage)> BeginDataCenterPubKeyExchangeAsync(
        PubKeyExchangeType exchangeType)
    {
        uint sessionId = GenerateRequestId();
        Logger.WriteLine($"[ShieldPro] Beginning exchange {exchangeType}, generated Session ID: {sessionId}");

        Logger.WriteLine("[ShieldPro] Generating ephemeral key pair.");
        _ecliptixSystemIdentityKeys.GenerateEphemeralKeyPair();

        var localBundleResult = _ecliptixSystemIdentityKeys.CreatePublicBundle();
        if (!localBundleResult.IsOk)
            throw new ShieldChainStepException(
                $"Failed to create local public bundle: {localBundleResult.UnwrapErr()}");
        var localBundle = localBundleResult.Unwrap();

        var protoBundle = localBundle.ToProtobufExchange()
                          ?? throw new ShieldChainStepException("Failed to convert local public bundle to protobuf.");

        var sessionResult = ShieldSession.Create(sessionId, localBundle, true);
        if (!sessionResult.IsOk)
            throw new ShieldChainStepException($"Failed to create session: {sessionResult.UnwrapErr()}");
        var session = sessionResult.Unwrap();

        var insertResult = await _sessionManager.InsertSession(sessionId, exchangeType, session);
        if (!insertResult.IsOk)
            throw new ShieldChainStepException($"Failed to insert session: {insertResult.UnwrapErr()}");

        var dhPublicKeyResult = session.GetCurrentSenderDhPublicKey();
        if (!dhPublicKeyResult.IsOk)
            throw new ShieldChainStepException($"Sender DH key not initialized: {dhPublicKeyResult.UnwrapErr()}");
        var dhPublicKey = dhPublicKeyResult.Unwrap();

        Logger.WriteLine($"[ShieldPro] Initial DH Public Key: {Convert.ToHexString(dhPublicKey)}");

        var pubKeyExchange = new PubKeyExchange
        {
            State = PubKeyExchangeState.Init,
            OfType = exchangeType,
            Payload = protoBundle.ToByteString(),
            InitialDhPublicKey = ByteString.CopyFrom(dhPublicKey)
        };

        return (sessionId, pubKeyExchange);
    }

    protected override async void PostStop()
    {
        base.PostStop();
    }

    protected override void PreStart()
    {
        _logger.LogInformation("MainShieldPro actor '{ActorPath}' is up and running.", Context.Self.Path);
        base.PreStart();
    }

    public static Props Build(EcliptixSystemIdentityKeys localKeys, IActorRef ecliptixProtocolConnectionsManagerActor,
        ILogger<EcliptixProtocolSystemActor> logger)
        => Props.Create(() =>
            new EcliptixProtocolSystemActor(localKeys, ecliptixProtocolConnectionsManagerActor, logger));
}