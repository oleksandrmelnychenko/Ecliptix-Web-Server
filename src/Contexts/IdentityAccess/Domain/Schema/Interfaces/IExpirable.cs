namespace Ecliptix.IdentityAccess.Domain.Schema.Interfaces;

public interface IExpirable
{
    DateTimeOffset ExpiresAt { get; }
}
