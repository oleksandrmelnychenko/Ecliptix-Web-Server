using System.Diagnostics;

namespace Ecliptix.Core.Infrastructure.Crypto;

/// <summary>
/// High-performance timing utility that avoids allocations.
/// </summary>
internal readonly struct ValueStopwatch
{
    private readonly long _startTimestamp;

    private ValueStopwatch(long startTimestamp)
    {
        _startTimestamp = startTimestamp;
    }

    public static ValueStopwatch StartNew() => new(Stopwatch.GetTimestamp());

    public TimeSpan Elapsed => new((long)((Stopwatch.GetTimestamp() - _startTimestamp) / (double)Stopwatch.Frequency * TimeSpan.TicksPerSecond));
}