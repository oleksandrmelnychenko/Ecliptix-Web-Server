namespace Ecliptix.Utilities.Configuration;

public static class TimeoutConfiguration
{
    public static class Actor
    {
#if DEBUG
        public static TimeSpan AskTimeout => Timeout.InfiniteTimeSpan;
        public static TimeSpan SupervisionTimeout => Timeout.InfiniteTimeSpan;
        public static TimeSpan StreamingTimeout => Timeout.InfiniteTimeSpan;
#else
        public static TimeSpan AskTimeout => TimeSpan.FromSeconds(30);
        public static TimeSpan SupervisionTimeout => TimeSpan.FromMinutes(5);
        public static TimeSpan StreamingTimeout => TimeSpan.FromMinutes(6);
#endif
    }

    public static class Database
    {
#if DEBUG
        public static TimeSpan CommandTimeout => Timeout.InfiniteTimeSpan;
        public static TimeSpan ConnectionTimeout => TimeSpan.FromSeconds(30);
        public static TimeSpan CreateTimeout => Timeout.InfiniteTimeSpan;
        public static TimeSpan UpdateTimeout => Timeout.InfiniteTimeSpan;
        public static TimeSpan DeleteTimeout => Timeout.InfiniteTimeSpan;
        public static TimeSpan GetTimeout => Timeout.InfiniteTimeSpan;
        public static TimeSpan QueryTimeout => Timeout.InfiniteTimeSpan;
        public static TimeSpan ListTimeout => Timeout.InfiniteTimeSpan;
#else
        public static TimeSpan CommandTimeout => TimeSpan.FromSeconds(30);
        public static TimeSpan ConnectionTimeout => TimeSpan.FromSeconds(30);
        public static TimeSpan CreateTimeout => TimeSpan.FromSeconds(30);
        public static TimeSpan UpdateTimeout => TimeSpan.FromSeconds(30);
        public static TimeSpan DeleteTimeout => TimeSpan.FromSeconds(20);
        public static TimeSpan GetTimeout => TimeSpan.FromSeconds(10);
        public static TimeSpan QueryTimeout => TimeSpan.FromSeconds(15);
        public static TimeSpan ListTimeout => TimeSpan.FromSeconds(20);
#endif
    }

    public static class Network
    {
#if DEBUG
        public static TimeSpan RequestHeadersTimeout => TimeSpan.FromMinutes(10);
        public static TimeSpan KeepAliveTimeout => TimeSpan.FromHours(1);
        public static TimeSpan ShutdownGracefulTimeout => TimeSpan.FromMinutes(5);
        public static TimeSpan DrainActiveRequests => TimeSpan.FromSeconds(10);
#else
        public static TimeSpan RequestHeadersTimeout => TimeSpan.FromSeconds(30);
        public static TimeSpan KeepAliveTimeout => TimeSpan.FromMinutes(2);
        public static TimeSpan ShutdownGracefulTimeout => TimeSpan.FromMinutes(2);
        public static TimeSpan DrainActiveRequests => TimeSpan.FromSeconds(5);
#endif
    }

    public static class CircuitBreaker
    {
#if DEBUG
        public static TimeSpan CallTimeout => Timeout.InfiniteTimeSpan;
        public static TimeSpan ResetTimeout => Timeout.InfiniteTimeSpan;
        public static bool Enabled => false;
#else
        public static TimeSpan CallTimeout => TimeSpan.FromSeconds(30);
        public static TimeSpan ResetTimeout => TimeSpan.FromSeconds(30);
        public static bool Enabled => true;
#endif
    }

    public static class Operations
    {
#if DEBUG
        public static TimeSpan Create => Timeout.InfiniteTimeSpan;
        public static TimeSpan Update => Timeout.InfiniteTimeSpan;
        public static TimeSpan Delete => Timeout.InfiniteTimeSpan;
        public static TimeSpan Query => Timeout.InfiniteTimeSpan;
        public static TimeSpan MetricsUpdate => Timeout.InfiniteTimeSpan;
#else
        public static TimeSpan Create => TimeSpan.FromSeconds(30);
        public static TimeSpan Update => TimeSpan.FromSeconds(30);
        public static TimeSpan Delete => TimeSpan.FromSeconds(20);
        public static TimeSpan Query => TimeSpan.FromSeconds(15);
        public static TimeSpan MetricsUpdate => TimeSpan.FromSeconds(30);
#endif
    }

    public static string FormatForAkka(TimeSpan timeout)
    {
        return timeout == Timeout.InfiniteTimeSpan ? "infinite" : $"{timeout.TotalSeconds}s";
    }

    public static CancellationTokenSource CreateCancellationTokenSource(TimeSpan timeout)
    {
        return timeout == Timeout.InfiniteTimeSpan
            ? new CancellationTokenSource()
            : new CancellationTokenSource(timeout);
    }
}
