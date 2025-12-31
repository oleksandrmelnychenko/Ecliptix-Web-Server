namespace Ecliptix.Domain.Memberships.Persistors.QueryResults;

public record AccountSecureKeyUpdateResult(
    Guid AccountId,
    Guid MembershipId,
    int CredentialsVersion,
    int OpaqueKeyVersion,
    byte[] SecureKey,
    byte[] MaskingKey);
