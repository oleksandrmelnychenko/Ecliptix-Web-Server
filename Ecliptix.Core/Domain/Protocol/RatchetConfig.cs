using Ecliptix.Utilities;

namespace Ecliptix.Core.Domain.Protocol;

public sealed class RatchetConfig
{
    public static readonly RatchetConfig Default = new();

    private static uint DhRatchetEveryNMessages => 10;

    private static bool EnablePerMessageRatchet => false;

    private static bool RatchetOnNewDhKey => true;

    private static uint MaxMessagesWithoutRatchet => Constants.MaxMessagesWithoutRatchetDefault;

    private readonly TimeSpan _maxChainAge  = TimeSpan.FromHours(1);

    private bool ShouldRatchet(uint messageIndex, DateTime lastRatchetTime, bool receivedNewDhKey, DateTime currentTime)
    {
        if (EnablePerMessageRatchet)
        {
            return true;
        }

        if (RatchetOnNewDhKey && receivedNewDhKey)
        {
            return true;
        }

        if (messageIndex > 0 && messageIndex % DhRatchetEveryNMessages == 0)
        {
            return true;
        }

        if (currentTime - lastRatchetTime > _maxChainAge)
        {
            return true;
        }

        return messageIndex >= MaxMessagesWithoutRatchet;
    }

    public bool ShouldRatchet(uint messageIndex, DateTime lastRatchetTime, bool receivedNewDhKey)
    {
        return ShouldRatchet(messageIndex, lastRatchetTime, receivedNewDhKey, DateTime.UtcNow);
    }
}
