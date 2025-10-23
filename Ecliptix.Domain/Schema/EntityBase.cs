using System.ComponentModel.DataAnnotations;
using Ecliptix.Domain.Schema.Interfaces;

namespace Ecliptix.Domain.Schema;

public abstract class EntityBase : IEntity, IAuditable, IConcurrent
{
    public long Id { get; set; }
    public Guid UniqueId { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public bool IsDeleted { get; set; }

    [Timestamp]
    public byte[] RowVersion { get; set; } = Array.Empty<byte>();
}