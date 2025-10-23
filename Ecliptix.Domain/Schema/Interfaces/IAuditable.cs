namespace Ecliptix.Domain.Schema.Interfaces;

public interface IAuditable
{
    DateTimeOffset CreatedAt { get; set; }
    DateTimeOffset UpdatedAt { get; set; }
    bool IsDeleted { get; set; }
}
