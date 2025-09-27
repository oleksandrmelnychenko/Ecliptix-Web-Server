using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Utilities;
using OtpNet;

namespace Ecliptix.Domain.Memberships;

public sealed class OneTimePassword
{
    private readonly byte[] _otpSecretKey = KeyGeneration.GenerateRandomKey(OtpHashMode.Sha256);

    private Option<OtpQueryRecord> _otpQueryRecord = Option<OtpQueryRecord>.None;

    public bool IsActive { get; private set; }
    public DateTime ExpiresAt { get; internal set; } = DateTime.UtcNow.AddSeconds(30);
    public Guid UniqueIdentifier { get; set; }

    public Result<(OtpQueryRecord Record, string PlainOtp), VerificationFlowFailure> Generate(
        PhoneNumberQueryRecord phoneNumberQueryRecord, Guid flowUniqueIdentifier)
    {
        return Result<(OtpQueryRecord, string), VerificationFlowFailure>.Try(
            () =>
            {
                Totp totp = new(_otpSecretKey, mode: OtpHashMode.Sha256);
                string otp = totp.ComputeTotp();

                (string hash, string salt) = OneTimePasswordHashing.HashOtp(otp);
                OtpQueryRecord otpQueryRecord = new()
                {
                    FlowUniqueId = flowUniqueIdentifier,
                    PhoneNumberIdentifier = phoneNumberQueryRecord.UniqueId,
                    OtpHash = hash,
                    OtpSalt = salt,
                    ExpiresAt = ExpiresAt,
                    IsActive = true,
                    Status = VerificationFlowStatus.Pending
                };

                IsActive = true;
                _otpQueryRecord = Option<OtpQueryRecord>.Some(otpQueryRecord);

                return (otpQueryRecord, otp);
            },
            ex => VerificationFlowFailure.OtpGenerationFailed(
                VerificationFlowMessageKeys.OtpGenerationFailed, ex));
    }

    private void ConsumeOtp()
    {
        IsActive = false;
    }

    public bool Verify(string code)
    {
        if (!IsValidForVerification()) return false;

        if (!HasExpired()) return PerformVerification(code);

        ConsumeOtp();
        return false;
    }

    private bool IsValidForVerification()
    {
        return _otpQueryRecord.HasValue && IsActive;
    }

    private bool HasExpired()
    {
        if (!_otpQueryRecord.HasValue) return true;

        OtpQueryRecord record = _otpQueryRecord.Value!;
        return DateTime.UtcNow > record.ExpiresAt;
    }

    private bool PerformVerification(string code)
    {
        OtpQueryRecord record = _otpQueryRecord.Value!;

        if (!OneTimePasswordHashing.VerifyOtp(code, record.OtpHash, record.OtpSalt)) return false;

        Result<bool, VerificationFlowFailure> totpVerificationResult = Result<bool, VerificationFlowFailure>.Try(
            () =>
            {
                Totp totp = new(_otpSecretKey, mode: OtpHashMode.Sha256);
                return totp.VerifyTotp(code, out _, new VerificationWindow(10));
            },
            _ => VerificationFlowFailure.InvalidOtp());

        bool isValid = totpVerificationResult.UnwrapOr(false);
        if (isValid) ConsumeOtp();

        return isValid;
    }

    public static OneTimePassword FromExisting(OtpQueryRecord record)
    {
        var otp = new OneTimePassword
        {
            UniqueIdentifier = record.UniqueIdentifier,
            ExpiresAt = record.ExpiresAt,
            IsActive = record.IsActive
        };
        otp._otpQueryRecord = Option<OtpQueryRecord>.Some(record);
        return otp;
    }
}