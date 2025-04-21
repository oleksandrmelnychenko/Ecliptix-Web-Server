using Akka.Actor;
using Ecliptix.Core.Actors.Messages;
using Ecliptix.Core.Protocol;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.PubKeyExchange;
using Google.Protobuf;

namespace Ecliptix.Core.Actors;

public record RespondToPubKeyExchangeCommand(uint ConnectId, PubKeyExchange PubKeyExchange);

public class EcliptixProtocolConnectActor : ReceiveActor
{
    private readonly EcliptixSystemIdentityKeys _ecliptixSystemIdentityKeys;
    
    private ConnectSession _connectSession = null!;

    private EcliptixProtocolConnectActor()
    {
        _ecliptixSystemIdentityKeys = EcliptixSystemIdentityKeys.Create(10).Unwrap();
        Become(Ready);    
    }

    private void Ready( )
    {
        ReceiveAsync<RespondToPubKeyExchangeCommand>(HandleRespondToPubKeyExchangeCommand);
    }

    private async Task HandleRespondToPubKeyExchangeCommand( RespondToPubKeyExchangeCommand command)
    {
        SodiumSecureMemoryHandle? rootKeyHandle = null;
        IActorRef parent = Context.Parent;
        uint connectId = command.ConnectId;
        
        try
        {
            _ecliptixSystemIdentityKeys.GenerateEphemeralKeyPair();

            Result<LocalPublicKeyBundle, ShieldFailure> localBundleResult = _ecliptixSystemIdentityKeys.CreatePublicBundle();
            if (!localBundleResult.IsOk)
            {
                throw new ShieldChainStepException(
                    $"Failed to create local public bundle: {localBundleResult.UnwrapErr()}");
            }
            
            LocalPublicKeyBundle localBundle = localBundleResult.Unwrap();

            PublicKeyBundle protoBundle = localBundle.ToProtobufExchange();

            Result<ConnectSession, ShieldFailure> sessionResult = ConnectSession.Create(command.ConnectId, localBundle, false);
            if (!sessionResult.IsOk)
            {
                throw new ShieldChainStepException($"Failed to create session: {sessionResult.UnwrapErr()}");
            }
            
            _connectSession = sessionResult.Unwrap();

            PublicKeyBundle peerBundleProto =
                Helpers.ParseFromBytes<PublicKeyBundle>(command.PubKeyExchange.Payload.ToByteArray());
            Result<LocalPublicKeyBundle, ShieldFailure> peerBundleResult = LocalPublicKeyBundle.FromProtobufExchange(peerBundleProto);

            if (!peerBundleResult.IsOk)
            {
                throw new ShieldChainStepException($"Failed to convert peer bundle: {peerBundleResult.UnwrapErr()}");
            }
            
            LocalPublicKeyBundle peerBundle = peerBundleResult.Unwrap();

            Result<bool, ShieldFailure> spkValidResult = EcliptixSystemIdentityKeys.VerifyRemoteSpkSignature(
                peerBundle.IdentityEd25519,
                peerBundle.SignedPreKeyPublic,
                peerBundle.SignedPreKeySignature);
            
            if (!spkValidResult.IsOk || !spkValidResult.Unwrap())
            {
                throw new ShieldChainStepException(
                    $"SPK signature validation failed: {(spkValidResult.IsOk ? "Invalid signature" : spkValidResult.UnwrapErr())}");
            }

            Result<SodiumSecureMemoryHandle, ShieldFailure> deriveResult = _ecliptixSystemIdentityKeys.CalculateSharedSecretAsRecipient(
                peerBundle.IdentityX25519,
                peerBundle.EphemeralX25519,
                peerBundle.OneTimePreKeys.FirstOrDefault()?.PreKeyId,
                EcliptixProtocolSystem.X3dhInfo);
            if (!deriveResult.IsOk)
            {
                throw new ShieldChainStepException($"Shared secret derivation failed: {deriveResult.UnwrapErr()}");
            }
            
            rootKeyHandle = deriveResult.Unwrap();

            byte[] rootKeyBytes = new byte[Constants.X25519KeySize];
            rootKeyHandle.Read(rootKeyBytes.AsSpan());

            _connectSession.SetPeerBundle(peerBundle);
            _connectSession.SetConnectionState(PubKeyExchangeState.Pending);

            byte[]? peerDhKey = command.PubKeyExchange.InitialDhPublicKey.ToByteArray();

            Result<Unit, ShieldFailure> finalizeResult = _connectSession.FinalizeChainAndDhKeys(rootKeyBytes, peerDhKey);
            if (!finalizeResult.IsOk)
            {
                throw new ShieldChainStepException($"Failed to finalize chain keys: {finalizeResult.UnwrapErr()}");
            }

            Result<Unit, ShieldFailure> stateResult = _connectSession.SetConnectionState(PubKeyExchangeState.Complete);
            if (!stateResult.IsOk)
            {
                throw new ShieldChainStepException($"Failed to set Complete state: {stateResult.UnwrapErr()}");
            }

            SodiumInterop.SecureWipe(rootKeyBytes);

            Result<byte[]?, ShieldFailure> dhPublicKeyResult = _connectSession.GetCurrentSenderDhPublicKey();
            if (!dhPublicKeyResult.IsOk)
            {
                throw new ShieldChainStepException($"Failed to get sender DH key: {dhPublicKeyResult.UnwrapErr()}");
            }
            
            byte[]? dhPublicKey = dhPublicKeyResult.Unwrap();

            PubKeyExchange pubKeyExchange = new()
            {
                State = PubKeyExchangeState.Pending,
                OfType = command.PubKeyExchange.OfType,
                Payload = protoBundle.ToByteString(),
                InitialDhPublicKey = ByteString.CopyFrom(dhPublicKey)
            };

            parent.Tell(new ConnectInitializationSuccess(connectId, pubKeyExchange, Self));
        }
        catch (Exception exc)
        {
            _connectSession.Dispose();

            parent.Tell(new ConnectInitializationFailure(connectId, exc, Self));
        }
        finally
        {
            rootKeyHandle?.Dispose();
        }
    }
    
    protected override void PostStop()
    {
        _connectSession?.Dispose();
        base.PostStop();
    }
    
    public static Props Build()
    {
        return Props.Create(() => new EcliptixProtocolConnectActor());
    }
}