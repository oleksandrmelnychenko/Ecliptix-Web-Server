using System.Threading;

namespace Ecliptix.IdentityAccess.Domain.Schema.Auditing;

public static class StatusChangeContextAccessor
{
    private static readonly AsyncLocal<StatusChangeContext?> CurrentContext = new();

    public static StatusChangeContext? Context => CurrentContext.Value;

    public static IDisposable BeginScope(StatusChangeContext context)
    {
        StatusChangeContext? prior = CurrentContext.Value;
        CurrentContext.Value = context;
        return new Scope(prior);
    }

    private sealed class Scope(StatusChangeContext? prior) : IDisposable
    {
        private bool _disposed;

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            CurrentContext.Value = prior;
            _disposed = true;
        }
    }
}
