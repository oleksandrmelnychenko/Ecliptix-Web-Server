namespace Ecliptix.Core.Middleware.Models;

public class BlockInfo
{
    public string IpAddress { get; set; } = string.Empty;
    public DateTime BlockedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public string Reason { get; set; } = string.Empty;
}