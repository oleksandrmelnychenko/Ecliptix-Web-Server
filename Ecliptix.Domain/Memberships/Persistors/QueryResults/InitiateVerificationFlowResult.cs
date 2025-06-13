namespace Ecliptix.Domain.Memberships.Persistors.QueryResults;

internal record InitiateVerificationFlowResult
{
    public Guid UniqueIdentifier { get; init; }
    public Guid PhoneNumberIdentifier { get; init; }
    public Guid AppDeviceIdentifier { get; init; }
    public long? ConnectId { get; init; }
    public DateTime ExpiresAt { get; init; }
    public string Status { get; init; } = string.Empty;
    public string Purpose { get; init; } = string.Empty;
    public short OtpCount { get; init; }
    public string Outcome { get; init; } = string.Empty;
    public Guid? Otp_UniqueIdentifier { get; init; }
    public Guid? Otp_FlowUniqueId { get; init; }
    public string? Otp_OtpHash { get; init; }
    public string? Otp_OtpSalt { get; init; }
    public DateTime? Otp_ExpiresAt { get; init; }
    public string? Otp_Status { get; init; }
    public bool? Otp_IsActive { get; init; }
}