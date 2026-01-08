using Akka.Actor;
using Akka.Serialization;
using Ecliptix.Protobuf.ProtocolState;
using Google.Protobuf;

namespace Ecliptix.Core.Infrastructure.Serialization;

public class Base64SessionStateSerializer : SerializerWithStringManifest
{
    private const string EcliptixSessionStateManifest = "EcliptixSessionState";

    public Base64SessionStateSerializer(ExtendedActorSystem system) : base(system)
    {
    }

    public override int Identifier => 100;

    public override string Manifest(object o)
    {
        return o switch
        {
            EcliptixSessionState => EcliptixSessionStateManifest,
            _ => throw new ArgumentException($"Unknown type: {o.GetType()}")
        };
    }

    public override byte[] ToBinary(object obj)
    {
        return obj switch
        {
            EcliptixSessionState state => state.ToByteArray(),
            _ => throw new ArgumentException($"Cannot serialize unknown type: {obj.GetType()}")
        };
    }

    public override object FromBinary(byte[] bytes, string manifest)
    {
        return manifest switch
        {
            EcliptixSessionStateManifest => EcliptixSessionState.Parser.ParseFrom(bytes),
            _ => throw new ArgumentException($"Unknown manifest: {manifest}")
        };
    }
}
