namespace Ecliptix.Domain.Memberships.Persistors.QueryResults;

public record AccountSecureKeyUpdateResult(
    Guid AccountId,
    Guid MembershipId,
    int CredentialsVersion,
    byte[] SecureKey,
    byte[] MaskingKey);
