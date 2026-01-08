namespace Ecliptix.IdentityAccess.Domain.Persistors.QueryResults;

public record AccountSecureKeyUpdateResult(
    Guid AccountId,
    Guid MembershipId,
    int CredentialsVersion,
    int OpaqueKeyVersion,
    byte[] SecureKey,
    byte[] MaskingKey);
