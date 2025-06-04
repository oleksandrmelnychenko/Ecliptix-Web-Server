namespace Ecliptix.Domain.Memberships.Persistors.Utilities;

public readonly struct CreateOtpRecordResult(Guid otpUniqueId)
{
    public readonly Guid OtpUniqueId = otpUniqueId;
}