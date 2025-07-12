using Akka.Actor;
using Akka.Serialization;
using Ecliptix.Protobuf.ProtocolState;
using Google.Protobuf;

namespace Ecliptix.Domain.Utilities;

public class ByteArraySessionStateSerializer : SerializerWithStringManifest
{
    public ByteArraySessionStateSerializer(ExtendedActorSystem system) : base(system)
    {
    }

    public override int Identifier => 100;

    public override string Manifest(object o) => "EcliptixSessionState";

    public override byte[] ToBinary(object obj)
    {
        return ((EcliptixSessionState)obj).ToByteArray();
    }

    public override object FromBinary(byte[] bytes, string manifest)
    {
        return EcliptixSessionState.Parser.ParseFrom(bytes);
    }
}