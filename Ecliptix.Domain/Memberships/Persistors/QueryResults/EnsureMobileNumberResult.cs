namespace Ecliptix.Domain.Memberships.Persistors.QueryResults;

internal class EnsureMobileNumberResult
{
    public Guid UniqueId { get; set; }
    public string Outcome { get; set; } = string.Empty;
    public bool Success { get; set; }
}