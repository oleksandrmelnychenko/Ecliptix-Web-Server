namespace Ecliptix.Core.Protocol;

public static class Constants
{
    public const int X25519KeySize = 32;
    public const uint CacheWindowSize = 1000;
    public static readonly TimeSpan RotationTimeout = TimeSpan.FromSeconds(3600);
   
    public static ReadOnlySpan<byte> ChainInfo => [0x01];
    public static ReadOnlySpan<byte> MsgInfo => [0x02];
}