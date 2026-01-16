namespace Ecliptix.IdentityAccess.Domain.Persistors.QueryResults;

public record AccountMaskingKeyEnsureResult(
    int CredentialsVersion,
    bool Updated);
