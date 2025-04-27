namespace Ecliptix.Core.Protocol;

public sealed class SessionHolder(ConnectSession session)
{
    public ConnectSession Session { get; } = session ?? throw new ArgumentNullException(nameof(session));
    public SemaphoreSlim Lock { get; } = new(1, 1);
}