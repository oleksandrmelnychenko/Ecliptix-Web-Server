using System;

namespace Ecliptix.Security.Opaque.Models;

public record MembershipOpaqueQueryRecord(string MobileNumber, byte[]? RegistrationRecord, Guid AccountId, int OpaqueKeyVersion);
public record AuthContextTokenResponse
{
    public byte[] ContextToken { get; init; } = [];
    public Guid MembershipId { get; init; }
    public Guid MobileNumberId { get; init; }
    public DateTime ExpiresAt { get; init; }
};
