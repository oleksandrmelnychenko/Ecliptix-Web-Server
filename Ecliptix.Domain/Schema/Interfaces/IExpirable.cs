namespace Ecliptix.Domain.Schema.Interfaces;

public interface IExpirable
{
    DateTimeOffset ExpiresAt { get; }
}
