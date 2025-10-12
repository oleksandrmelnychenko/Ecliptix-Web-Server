using Ecliptix.Utilities;

namespace Ecliptix.Core.Domain.Protocol;

public sealed class RatchetConfig
{
    public static readonly RatchetConfig Default = new();

    public uint DhRatchetEveryNMessages { get; init; } = 10;

    public bool EnablePerMessageRatchet { get; init; } = false;

    public bool RatchetOnNewDhKey { get; init; } = true;

    public TimeSpan MaxChainAge { get; init; } = TimeSpan.FromHours(1);

    public uint MaxMessagesWithoutRatchet { get; init; } = Constants.MaxMessagesWithoutRatchetDefault;

    public bool ShouldRatchet(uint messageIndex, DateTime lastRatchetTime, bool receivedNewDhKey, DateTime currentTime)
    {
        if (EnablePerMessageRatchet)
            return true;

        if (RatchetOnNewDhKey && receivedNewDhKey)
            return true;

        if (messageIndex > 0 && messageIndex % DhRatchetEveryNMessages == 0)
            return true;

        if (currentTime - lastRatchetTime > MaxChainAge)
            return true;

        if (messageIndex >= MaxMessagesWithoutRatchet)
            return true;

        return false;
    }

    public bool ShouldRatchet(uint messageIndex, DateTime lastRatchetTime, bool receivedNewDhKey)
    {
        return ShouldRatchet(messageIndex, lastRatchetTime, receivedNewDhKey, DateTime.UtcNow);
    }
}