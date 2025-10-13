namespace Ecliptix.Domain.Schema.Entities;

public class LoginAttemptEntity : EntityBase
{
    public Guid AccountId { get; set; }
    
    public Guid? MobileNumberId { get; set; }
    
    public string? Outcome { get; set; }

    public bool IsSuccess { get; set; }

    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    public DateTime? LockedUntil { get; set; }

    public string? Status { get; set; }

    public string? ErrorMessage { get; set; }

    public string? SessionId { get; set; }

    public DateTime AttemptedAt { get; set; } = DateTime.UtcNow;

    public DateTime? SuccessfulAt { get; set; }

    public virtual AccountEntity Account { get; set; }
    public virtual MobileNumberEntity? MobileNumber { get; set; }
}