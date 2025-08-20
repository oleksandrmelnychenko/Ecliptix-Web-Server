using Akka.Actor;
using Akka.Serialization;
using Ecliptix.Protobuf.ProtocolState;
using Google.Protobuf;

namespace Ecliptix.Domain.Utilities;

public class ByteArraySessionStateSerializer : SerializerWithStringManifest
{
    private const string EcliptixSessionStateManifest = "EcliptixSessionState";
    private const string IdentityKeysStateManifest = "IdentityKeysState";
    private const string RatchetStateManifest = "RatchetState";
    private const string OneTimePreKeySecretManifest = "OneTimePreKeySecret";
    private const string ChainStepStateManifest = "ChainStepState";
    private const string CachedMessageKeyManifest = "CachedMessageKey";

    public ByteArraySessionStateSerializer(ExtendedActorSystem system) : base(system)
    {
    }

    public override int Identifier => 100;

    public override string Manifest(object o)
    {
        return o switch
        {
            EcliptixSessionState => EcliptixSessionStateManifest,
            IdentityKeysState => IdentityKeysStateManifest,
            RatchetState => RatchetStateManifest,
            OneTimePreKeySecret => OneTimePreKeySecretManifest,
            ChainStepState => ChainStepStateManifest,
            CachedMessageKey => CachedMessageKeyManifest,
            _ => throw new ArgumentException($"Unknown type: {o.GetType()}")
        };
    }

    public override byte[] ToBinary(object obj)
    {
        return obj switch
        {
            EcliptixSessionState state => state.ToByteArray(),
            IdentityKeysState keys => keys.ToByteArray(),
            RatchetState ratchet => ratchet.ToByteArray(),
            OneTimePreKeySecret otpk => otpk.ToByteArray(),
            ChainStepState chain => chain.ToByteArray(),
            CachedMessageKey key => key.ToByteArray(),
            _ => throw new ArgumentException($"Cannot serialize unknown type: {obj.GetType()}")
        };
    }

    public override object FromBinary(byte[] bytes, string manifest)
    {
        return manifest switch
        {
            EcliptixSessionStateManifest => EcliptixSessionState.Parser.ParseFrom(bytes),
            IdentityKeysStateManifest => IdentityKeysState.Parser.ParseFrom(bytes),
            RatchetStateManifest => RatchetState.Parser.ParseFrom(bytes),
            OneTimePreKeySecretManifest => OneTimePreKeySecret.Parser.ParseFrom(bytes),
            ChainStepStateManifest => ChainStepState.Parser.ParseFrom(bytes),
            CachedMessageKeyManifest => CachedMessageKey.Parser.ParseFrom(bytes),
            _ => throw new ArgumentException($"Unknown manifest: {manifest}")
        };
    }
}