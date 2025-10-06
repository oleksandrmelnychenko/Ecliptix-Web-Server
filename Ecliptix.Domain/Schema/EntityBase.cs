using System.ComponentModel.DataAnnotations;

namespace Ecliptix.Domain.Schema;

public abstract class EntityBase
{
    public long Id { get; set; }
    public Guid UniqueId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public bool IsDeleted { get; set; }
}