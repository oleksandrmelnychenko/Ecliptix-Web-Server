using Google.Protobuf;

namespace Ecliptix.SharedKernel;

public static class Helpers
{
    public static ByteString GuidToByteString(Guid guid)
    {
        Span<byte> bytes = stackalloc byte[16];
        guid.TryWriteBytes(bytes);

        (bytes[0], bytes[1], bytes[2], bytes[3]) = (bytes[3], bytes[2], bytes[1], bytes[0]);
        (bytes[4], bytes[5]) = (bytes[5], bytes[4]);
        (bytes[6], bytes[7]) = (bytes[7], bytes[6]);

        return ByteString.CopyFrom(bytes);
    }

    public static Guid FromByteStringToGuid(ByteString byteString)
    {
        Span<byte> bytes = stackalloc byte[16];
        byteString.Span.CopyTo(bytes);

        (bytes[0], bytes[1], bytes[2], bytes[3]) = (bytes[3], bytes[2], bytes[1], bytes[0]);
        (bytes[4], bytes[5]) = (bytes[5], bytes[4]);
        (bytes[6], bytes[7]) = (bytes[7], bytes[6]);

        return new Guid(bytes);
    }

    public static bool TryFromByteStringToGuid(ByteString byteString, out Guid result)
    {
        if (byteString.Length != 16)
        {
            result = default;
            return false;
        }

        Span<byte> bytes = stackalloc byte[16];
        byteString.Span.CopyTo(bytes);

        (bytes[0], bytes[1], bytes[2], bytes[3]) = (bytes[3], bytes[2], bytes[1], bytes[0]);
        (bytes[4], bytes[5]) = (bytes[5], bytes[4]);
        (bytes[6], bytes[7]) = (bytes[7], bytes[6]);

        result = new Guid(bytes);
        return true;
    }

    public static bool TryParseProto<T>(ByteString byteString, MessageParser<T> parser, out T? result)
        where T : class, IMessage<T>
    {
        try
        {
            result = parser.ParseFrom(byteString);
            return true;
        }
        catch
        {
            result = default;
            return false;
        }
    }
}
