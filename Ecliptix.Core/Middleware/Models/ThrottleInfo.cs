namespace Ecliptix.Core.Middleware.Models;

public class ThrottleInfo
{
    public int RequestCount { get; set; }
    public int FailureCount { get; set; }
    public DateTime WindowStart { get; set; } = DateTime.UtcNow;
    public DateTime LastRequest { get; set; } = DateTime.UtcNow;
    public DateTime LastFailure { get; set; }
}