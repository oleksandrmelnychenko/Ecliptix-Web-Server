using System.Diagnostics;
using System.Text;
using Ecliptix.Domain.Utilities;

namespace Ecliptix.Core.Domain.Protocol;

public sealed class PerformanceProfiler
{
    private readonly Dictionary<string, ProfileData> _metrics = new();
    private readonly Lock _lock = new();
    private readonly DateTime _startTime = DateTime.UtcNow;

    public IDisposable StartOperation(string operationName)
    {
        return new OperationTimer(this, operationName);
    }

    private void RecordOperation(string operationName, TimeSpan duration)
    {
        lock (_lock)
        {
            if (!_metrics.TryGetValue(operationName, out ProfileData? data))
            {
                data = new ProfileData();
                _metrics[operationName] = data;
            }

            data.RecordDuration(duration);
        }
    }

    public Dictionary<string, (long Count, double AvgMs, double MaxMs, double MinMs)> GetMetrics()
    {
        lock (_lock)
        {
            return _metrics.ToDictionary(
                kvp => kvp.Key,
                kvp => (
                    kvp.Value.Count,
                    kvp.Value.AverageMs,
                    kvp.Value.MaxMs,
                    kvp.Value.MinMs
                ));
        }
    }

    public void Reset()
    {
        lock (_lock)
        {
            _metrics.Clear();
        }
    }

    public string GetReport()
    {
        StringBuilder report = new();
        report.AppendLine("=== Protocol Performance Report ===");
        report.AppendLine($"Session Duration: {DateTime.UtcNow - _startTime:hh\\:mm\\:ss}");
        report.AppendLine();

        Dictionary<string, (long Count, double AvgMs, double MaxMs, double MinMs)> metrics = GetMetrics();

        if (metrics.Count == 0)
        {
            report.AppendLine(ProtocolMessages.NoPerformanceDataCollected);
            return report.ToString();
        }

        report.AppendLine(ProtocolMessages.OperationHeader.PadRight(Constants.OperationColumnWidth) + 
                         ProtocolMessages.CountHeader.PadLeft(Constants.CountColumnWidth) + 
                         ProtocolMessages.AverageHeader.PadLeft(Constants.MetricsColumnWidth) + 
                         ProtocolMessages.MaxHeader.PadLeft(Constants.MetricsColumnWidth) + 
                         ProtocolMessages.MinHeader.PadLeft(Constants.MetricsColumnWidth));
        report.AppendLine(new string('-', Constants.TotalReportWidth));

        foreach ((string operation, (long count, double avgMs, double maxMs, double minMs)) in 
                 metrics.OrderByDescending(x => x.Value.Count))
        {
            report.AppendLine(
                operation.PadRight(Constants.OperationColumnWidth) +
                count.ToString().PadLeft(Constants.CountColumnWidth) +
                avgMs.ToString(Constants.MetricsFormat).PadLeft(Constants.MetricsColumnWidth) +
                maxMs.ToString(Constants.MetricsFormat).PadLeft(Constants.MetricsColumnWidth) +
                minMs.ToString(Constants.MetricsFormat).PadLeft(Constants.MetricsColumnWidth));
        }

        return report.ToString();
    }

    private sealed class OperationTimer : IDisposable
    {
        private readonly PerformanceProfiler _profiler;
        private readonly string _operationName;
        private readonly Stopwatch _stopwatch;
        private bool _disposed;

        public OperationTimer(PerformanceProfiler profiler, string operationName)
        {
            _profiler = profiler;
            _operationName = operationName;
            _stopwatch = Stopwatch.StartNew();
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            _stopwatch.Stop();
            _profiler.RecordOperation(_operationName, _stopwatch.Elapsed);
        }
    }

    private sealed class ProfileData
    {
        private long _count;
        private double _totalMs;
        private double _maxMs = double.MinValue;
        private double _minMs = double.MaxValue;

        public long Count => _count;
        public double AverageMs => _count > 0 ? _totalMs / _count : 0;
        public double MaxMs => _maxMs == double.MinValue ? 0 : _maxMs;
        public double MinMs => _minMs == double.MaxValue ? 0 : _minMs;

        public void RecordDuration(TimeSpan duration)
        {
            double ms = duration.TotalMilliseconds;

            _count++;
            _totalMs += ms;

            if (ms > _maxMs) _maxMs = ms;
            if (ms < _minMs) _minMs = ms;
        }
    }
}