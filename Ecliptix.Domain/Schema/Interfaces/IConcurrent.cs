namespace Ecliptix.Domain.Schema.Interfaces;

public interface IConcurrent
{
    byte[] RowVersion { get; set; }
}
