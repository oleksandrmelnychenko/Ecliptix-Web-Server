namespace Ecliptix.Core.Protocol;

public sealed class SessionHolder(ShieldSession session)
{
    public ShieldSession Session { get; } = session ?? throw new ArgumentNullException(nameof(session));
    public SemaphoreSlim Lock { get; } = new(1, 1);
}