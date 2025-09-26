namespace Ecliptix.Domain.Memberships.OPAQUE;

/// <summary>
/// Query record for membership OPAQUE authentication
/// </summary>
public record MembershipOpaqueQueryRecord(string MobileNumber, byte[] RegistrationRecord, byte[] MaskingKey);

/// <summary>
/// Response containing authentication context token information
/// </summary>
public record AuthContextTokenResponse
{
    public byte[] ContextToken { get; init; } = [];
    public Guid MembershipId { get; init; }
    public Guid MobileNumberId { get; init; }
    public DateTime ExpiresAt { get; init; }
};