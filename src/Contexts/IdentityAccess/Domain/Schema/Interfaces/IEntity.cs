namespace Ecliptix.IdentityAccess.Domain.Schema.Interfaces;

public interface IEntity
{
    long Id { get; }
    Guid UniqueId { get; }
}
