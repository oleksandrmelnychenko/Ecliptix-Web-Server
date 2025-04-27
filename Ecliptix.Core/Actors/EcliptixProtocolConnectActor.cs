using Akka.Actor;
using Ecliptix.Core.Protocol;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.PubKeyExchange;

namespace Ecliptix.Core.Actors;

public class EcliptixProtocolConnectActor : ReceiveActor
{
    private readonly uint _connectId;
    private EcliptixSystemIdentityKeys _ecliptixSystemIdentityKeys;
    
    private readonly ILogger<EcliptixProtocolSystemActor> _logger;


    public EcliptixProtocolConnectActor(uint connectId, PubKeyExchange peerPubKeyExchange)
    {
        _connectId = connectId;
        Result<EcliptixSystemIdentityKeys, ShieldFailure> systemIdentityKeysResult = 
            EcliptixSystemIdentityKeys.Create(10);

        _ecliptixSystemIdentityKeys = systemIdentityKeysResult.Unwrap();
        _ecliptixSystemIdentityKeys.GenerateEphemeralKeyPair().IgnoreResult();
        
        
        
        
    }
    
    public static Props Build(uint connectId, PubKeyExchange peerPubKeyExchange)
    {
        return Props.Create(() => new EcliptixProtocolConnectActor(connectId, peerPubKeyExchange));
    }
}