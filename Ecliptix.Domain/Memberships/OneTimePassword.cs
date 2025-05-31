using Ecliptix.Domain.Persistors.QueryRecords;
using Ecliptix.Domain.Utilities;
using Microsoft.Extensions.Localization;
using OtpNet;

namespace Ecliptix.Domain.Memberships;

public sealed class OneTimePassword(IStringLocalizer localizer)
{
    private readonly byte[] _otpSecretKey = KeyGeneration.GenerateRandomKey(OtpHashMode.Sha256);

    private Option<OtpQueryRecord> _otpQueryRecord = Option<OtpQueryRecord>.None;

    public bool IsActive { get; private set; }

    public DateTime ExpiresAt { get; } = DateTime.UtcNow.AddSeconds(20);

    public Guid UniqueIdentifier { get; set; }

    public void SetOtpQueryRecordIdentifier(Guid identifier) =>
        UniqueIdentifier = identifier;

    public async Task<Result<OtpQueryRecord, ShieldFailure>> SendAsync(
        PhoneNumberQueryRecord phoneNumberQueryRecord,
        Func<string, string, Task<Result<Unit, ShieldFailure>>> send)
    {
        Totp totp = new(secretKey: _otpSecretKey, mode: OtpHashMode.Sha256);
        string otp = totp.ComputeTotp();
        LocalizedString message = localizer["Auth code is: {0}", otp];

        Result<Unit, ShieldFailure> smsSentResult =
            await send(phoneNumberQueryRecord.PhoneNumber, message.Value);

        return smsSentResult.Match(
            ok: _ =>
            {
                (string hash, string salt) = OneTimePasswordHashing.HashOtp(otp);
                OtpQueryRecord otpQueryRecord = new()
                {
                    PhoneNumberIdentifier = phoneNumberQueryRecord.UniqueIdentifier,
                    OtpHash = hash,
                    OtpSalt = salt,
                    ExpiresAt = ExpiresAt
                };

                IsActive = true;
                _otpQueryRecord = Option<OtpQueryRecord>.Some(otpQueryRecord);
                return Result<OtpQueryRecord, ShieldFailure>.Ok(otpQueryRecord);
            },
            err: Result<OtpQueryRecord, ShieldFailure>.Err);
    }

    public void ConsumeOtp()
    {
        IsActive = false;
    }

    public Task<bool> VerifyAsync(string code)
    {
        if (!_otpQueryRecord.HasValue || !IsActive)
        {
            return Task.FromResult(false);
        }

        OtpQueryRecord? record = _otpQueryRecord.Value;
        if (DateTime.UtcNow > record!.ExpiresAt)
        {
            IsActive = false;
            return Task.FromResult(false);
        }

        bool isValid = OneTimePasswordHashing.VerifyOtp(code, record.OtpHash, record.OtpSalt);
        if (!isValid)
        {
            return Task.FromResult(false);
        }

        Totp totp = new(_otpSecretKey, mode: OtpHashMode.Sha256);
        isValid = totp.VerifyTotp(code, out _, new VerificationWindow(previous: 10, future: 0));

        if (isValid)
        {
            ConsumeOtp();
        }

        return Task.FromResult(isValid);
    }
}