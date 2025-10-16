namespace Ecliptix.Utilities;

public static class SharedConstants
{
    public const int StackAllocationThreshold = 256;
    public const int LargeStackAllocationThreshold = 512;
    public const int MaxStackAllocationThreshold = 1024;

    public const int Blake2bSaltSize = 16;
    public const int Blake2bPersonalSize = 16;

    public const int Sha256HashSize = 32;
    public const int Sha512HashSize = 64;

    public const int StandardKeySize = 32;
    public const int ExportKeySize = 64;

    public const int FingerprintDisplayLength = 16;

    public const int MinutesIn5MinuteWindow = 5;
    public const int MinutesInOneHour = 60;
    public const int HoursInOneHourWindow = 1;
}
