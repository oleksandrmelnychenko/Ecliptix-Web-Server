using System.Collections.Concurrent;
using Ecliptix.Core.Protocol;

namespace Ecliptix.Core.Domain.Protocol;

public enum LoadLevel
{
    Light,      // < 10 msg/sec
    Moderate,   // 10-50 msg/sec
    Heavy,      // 50-200 msg/sec
    Extreme     // > 200 msg/sec
}

public sealed class AdaptiveRatchetManager : IDisposable
{
    private readonly Lock _lock = new();
    private readonly ConcurrentQueue<DateTime> _messageTimestamps = new();
    private readonly Timer _loadAnalysisTimer;
    private readonly TimeSpan _analysisInterval = TimeSpan.FromSeconds(10);
    private readonly TimeSpan _messageWindowSize = TimeSpan.FromMinutes(1);
    
    private LoadLevel _currentLoad = LoadLevel.Light;
    private RatchetConfig _currentConfig;
    private double _averageMessageRate;
    private DateTime _lastConfigUpdate = DateTime.UtcNow;
    private bool _disposed;

    public AdaptiveRatchetManager(RatchetConfig baseConfig)
    {
        _currentConfig = baseConfig;
        
        _loadAnalysisTimer = new Timer(
            callback: _ => AnalyzeLoadAndAdjustConfig(),
            state: null,
            dueTime: _analysisInterval,
            period: _analysisInterval
        );
    }

    public LoadLevel CurrentLoad
    {
        get
        {
            lock (_lock)
            {
                return _currentLoad;
            }
        }
    }

    public RatchetConfig CurrentConfig
    {
        get
        {
            lock (_lock)
            {
                return _currentConfig;
            }
        }
    }

    public void RecordMessage()
    {
        if (_disposed) return;
        
        DateTime now = DateTime.UtcNow;
        _messageTimestamps.Enqueue(now);
        
        if (_messageTimestamps.Count > 10000)
        {
            CleanupOldTimestamps(now);
        }
    }

    private void CleanupOldTimestamps(DateTime now)
    {
        DateTime cutoff = now - _messageWindowSize;
        
        while (_messageTimestamps.TryPeek(out DateTime timestamp) && timestamp < cutoff)
        {
            _messageTimestamps.TryDequeue(out _);
        }
    }

    private void AnalyzeLoadAndAdjustConfig()
    {
        if (_disposed) return;
        
        try
        {
            DateTime now = DateTime.UtcNow;
            CleanupOldTimestamps(now);
            
            DateTime windowStart = now - _messageWindowSize;
            int messageCount = _messageTimestamps.Count(timestamp => timestamp >= windowStart);

            double messagesPerSecond = messageCount / _messageWindowSize.TotalSeconds;
            
            lock (_lock)
            {
                _averageMessageRate = messagesPerSecond;
                LoadLevel newLoad = DetermineLoadLevel(messagesPerSecond);

                if (newLoad == _currentLoad && (now - _lastConfigUpdate) <= TimeSpan.FromMinutes(5)) return;
                _currentLoad = newLoad;
                _currentConfig = CreateConfigForLoad(newLoad);
                _lastConfigUpdate = now;
                    
                Console.WriteLine($"[ADAPTIVE RATCHET] Load: {newLoad}, Rate: {messagesPerSecond:F1} msg/sec, DH Interval: {_currentConfig.DhRatchetEveryNMessages}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ADAPTIVE RATCHET] Error in load analysis: {ex.Message}");
        }
    }

    private static LoadLevel DetermineLoadLevel(double messagesPerSecond)
    {
        return messagesPerSecond switch
        {
            < 10 => LoadLevel.Light,
            < 50 => LoadLevel.Moderate,
            < 200 => LoadLevel.Heavy,
            _ => LoadLevel.Extreme
        };
    }

    private static RatchetConfig CreateConfigForLoad(LoadLevel load)
    {
        return load switch
        {
            LoadLevel.Light => new RatchetConfig
            {
                DhRatchetEveryNMessages = 5, 
                EnablePerMessageRatchet = false,
                RatchetOnNewDhKey = true,
                MaxChainAge = TimeSpan.FromMinutes(30),
                MaxMessagesWithoutRatchet = 100
            },
            
            LoadLevel.Moderate => new RatchetConfig
            {
                DhRatchetEveryNMessages = 10, 
                EnablePerMessageRatchet = false,
                RatchetOnNewDhKey = true,
                MaxChainAge = TimeSpan.FromMinutes(45),
                MaxMessagesWithoutRatchet = 200
            },
            
            LoadLevel.Heavy => new RatchetConfig
            {
                DhRatchetEveryNMessages = 25,  
                EnablePerMessageRatchet = false,
                RatchetOnNewDhKey = true,
                MaxChainAge = TimeSpan.FromHours(1),
                MaxMessagesWithoutRatchet = 500
            },
            
            LoadLevel.Extreme => new RatchetConfig
            {
                DhRatchetEveryNMessages = 50, 
                EnablePerMessageRatchet = false,
                RatchetOnNewDhKey = false,     
                MaxChainAge = TimeSpan.FromHours(2),
                MaxMessagesWithoutRatchet = 1000
            },
            
            _ => RatchetConfig.Default
        };
    }

    public (LoadLevel Load, double MessageRate, uint RatchetInterval, TimeSpan MaxAge) GetLoadMetrics()
    {
        lock (_lock)
        {
            return (_currentLoad, _averageMessageRate, _currentConfig.DhRatchetEveryNMessages, _currentConfig.MaxChainAge);
        }
    }

    public void ForceConfigUpdate(LoadLevel targetLoad)
    {
        lock (_lock)
        {
            _currentLoad = targetLoad;
            _currentConfig = CreateConfigForLoad(targetLoad);
            _lastConfigUpdate = DateTime.UtcNow;
            
            Console.WriteLine($"[ADAPTIVE RATCHET] Forced config update to {targetLoad}");
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        
        _disposed = true;
        _loadAnalysisTimer?.Dispose();
        
        while (_messageTimestamps.TryDequeue(out _))
        {
        }
        
        Console.WriteLine("[ADAPTIVE RATCHET] Manager disposed");
    }
}