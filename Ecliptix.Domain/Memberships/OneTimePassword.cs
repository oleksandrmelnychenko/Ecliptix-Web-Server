using System;
using System.Globalization;
using System.Security.Cryptography;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Utilities;

namespace Ecliptix.Domain.Memberships;

public sealed class OneTimePassword
{
    private static readonly TimeSpan DefaultTimeToLive = TimeSpan.FromSeconds(30);

    private readonly TimeSpan _timeToLive;
    private readonly Func<DateTimeOffset> _utcNow;

    private Guid _uniqueIdentifier;
    private Option<OtpQueryRecord> _otpQueryRecord = Option<OtpQueryRecord>.None;

    public OneTimePassword()
        : this(DefaultTimeToLive, static () => DateTimeOffset.UtcNow)
    {
    }

    public OneTimePassword(TimeSpan otpExpiration)
        : this(otpExpiration, static () => DateTimeOffset.UtcNow)
    {
    }

    private OneTimePassword(TimeSpan timeToLive, Func<DateTimeOffset> utcNow)
    {
        _timeToLive = timeToLive;
        _utcNow = utcNow;
    }

    public bool IsActive { get; private set; }
    public DateTimeOffset ExpiresAt { get; private set; }

    public Guid UniqueIdentifier
    {
        get => _uniqueIdentifier;
        set
        {
            _uniqueIdentifier = value;

            if (_otpQueryRecord.HasValue)
            {
                OtpQueryRecord record = _otpQueryRecord.Value!;
                _otpQueryRecord = Option<OtpQueryRecord>.Some(record with { UniqueIdentifier = value });
            }
        }
    }

    public Result<(OtpQueryRecord Record, string PlainOtp), VerificationFlowFailure> Generate(
        MobileNumberQueryRecord phoneNumberQueryRecord, Guid flowUniqueIdentifier)
    {
        return Result<(OtpQueryRecord, string), VerificationFlowFailure>.Try(
            () =>
            {
                string otp = GenerateOtpCode();
                DateTimeOffset expiresAt = _utcNow().Add(_timeToLive);

                (string hash, string salt) = OneTimePasswordHashing.HashOtp(otp);
                OtpQueryRecord otpQueryRecord = new()
                {
                    UniqueIdentifier = _uniqueIdentifier,
                    FlowUniqueId = flowUniqueIdentifier,
                    MobileNumberIdentifier = phoneNumberQueryRecord.UniqueId,
                    OtpHash = hash,
                    OtpSalt = salt,
                    ExpiresAt = expiresAt,
                    IsActive = true,
                    Status = OtpStatus.Active
                };

                ExpiresAt = expiresAt;
                IsActive = true;
                _otpQueryRecord = Option<OtpQueryRecord>.Some(otpQueryRecord);

                return (otpQueryRecord, otp);
            },
            ex => VerificationFlowFailure.OtpGenerationFailed(
                VerificationFlowMessageKeys.OtpGenerationFailed, ex));
    }

    public bool Verify(string code)
    {
        if (!IsValidForVerification())
        {
            return false;
        }

        if (!HasExpired())
        {
            return PerformVerification(code);
        }

        ConsumeOtp();
        return false;

    }

    private void ConsumeOtp()
    {
        IsActive = false;

        if (!_otpQueryRecord.HasValue)
        {
            return;
        }

        OtpQueryRecord record = _otpQueryRecord.Value!;
        _otpQueryRecord = Option<OtpQueryRecord>.Some(record with { IsActive = false });
    }

    private bool IsValidForVerification()
    {
        return _otpQueryRecord.HasValue && IsActive;
    }

    private bool HasExpired()
    {
        if (!_otpQueryRecord.HasValue)
        {
            return true;
        }

        OtpQueryRecord record = _otpQueryRecord.Value!;
        return _utcNow() > record.ExpiresAt;
    }

    private bool PerformVerification(string code)
    {
        OtpQueryRecord record = _otpQueryRecord.Value!;

        if (!OneTimePasswordHashing.VerifyOtp(code, record.OtpHash, record.OtpSalt))
        {
            return false;
        }

        ConsumeOtp();
        return true;
    }

    public static OneTimePassword FromExisting(OtpQueryRecord record)
    {
        OneTimePassword otp = new()
        {
            _uniqueIdentifier = record.UniqueIdentifier,
            ExpiresAt = record.ExpiresAt,
            IsActive = record.IsActive,
            _otpQueryRecord = Option<OtpQueryRecord>.Some(record)
        };
        return otp;
    }

    private static string GenerateOtpCode()
    {
        int value = RandomNumberGenerator.GetInt32(0, 1_000_000);
        return value.ToString("D6", CultureInfo.InvariantCulture);
    }
}
