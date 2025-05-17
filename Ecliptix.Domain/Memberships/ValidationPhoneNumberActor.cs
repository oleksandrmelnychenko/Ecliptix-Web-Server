using Akka.Actor;
using Akka.Event;
using Ecliptix.Domain.Utilities;
using PhoneNumbers;

namespace Ecliptix.Domain.Memberships;

public record ValidatePhoneNumberCommand(string PhoneNumber, string? DefaultRegion = null);

public enum CustomPhoneNumberType
{
    Unknown = 0,
    FixedLine = 1,
    Mobile = 2,
    TollFree = 3,
    PremiumRate = 4,
    SharedCost = 5,
    Voip = 6,
    PersonalNumber = 7,
    Pager = 8,
    Uan = 9,
    Voicemail = 10,
    FixedLineOrMobile = 11
}

public record PhoneNumberValidationResult
{
    public bool IsValid { get; init; }
    public string? ParsedPhoneNumberE164 { get; init; }
    public string? DetectedRegion { get; init; }
    public CustomPhoneNumberType NumberType { get; init; }
    public string? ErrorMessage { get; init; }
    public ValidationFailureReason? FailureReason { get; init; }

    public PhoneNumberValidationResult(string parsedPhoneNumberE164, string detectedRegion,
        CustomPhoneNumberType numberType)
    {
        IsValid = true;
        ParsedPhoneNumberE164 = parsedPhoneNumberE164;
        DetectedRegion = detectedRegion;
        NumberType = numberType;
    }

    public PhoneNumberValidationResult(string? errorMessage, ValidationFailureReason? failureReason = null,
        string? parsedNumberIfAvailable = null)
    {
        IsValid = false;
        ErrorMessage = errorMessage;
        FailureReason = failureReason;
        ParsedPhoneNumberE164 = parsedNumberIfAvailable;
        NumberType = CustomPhoneNumberType.Unknown;
    }
}

public enum ValidationFailureReason
{
    ParsingFailed,
    InvalidNumber,
    InvalidCountryCode,
    TooShort,
    TooLong,
    InvalidForRegion,
    PossibleButNotCertain,
    InternalError
}

public class PhoneNumberValidatorActor : ReceiveActor
{
    private readonly PhoneNumberUtil _phoneNumberUtil = PhoneNumberUtil.GetInstance();
    private readonly ILoggingAdapter _log = Context.GetLogger();

    private readonly int _cacheCapacity;
    private readonly Dictionary<string, PhoneNumberValidationResult> _cache = new();
    private readonly LinkedList<string> _lruTracker = new();

    public PhoneNumberValidatorActor(int cacheCapacity = 1000)
    {
        _cacheCapacity = cacheCapacity > 0 ? cacheCapacity : 1000;
        Receive<ValidatePhoneNumberCommand>(HandleValidatePhoneNumber);
    }

    private void HandleValidatePhoneNumber(ValidatePhoneNumberCommand command)
    {
        string originalPhoneNumberStr = command.PhoneNumber;
        _log.Debug("Received validation request for: {PhoneNumber}, DefaultRegion: {DefaultRegion}",
            originalPhoneNumberStr, command.DefaultRegion ?? "N/A");

        PhoneNumber parsedPhoneNumber;
        string e164FormatKey;

        try
        {
            string regionToParseWith =
                command.DefaultRegion ?? (originalPhoneNumberStr.StartsWith("+") ? "ZZ" : null);
            parsedPhoneNumber = _phoneNumberUtil.Parse(originalPhoneNumberStr, regionToParseWith);
            e164FormatKey = _phoneNumberUtil.Format(parsedPhoneNumber, PhoneNumberFormat.E164);

            if (_cache.TryGetValue(e164FormatKey, out PhoneNumberValidationResult? cachedResult))
            {
                _log.Debug("Cache hit for {Key}. Returning cached result.", e164FormatKey);
                UpdateLru(e164FormatKey);
                Sender.Tell(Result<PhoneNumberValidationResult, ShieldFailure>.Ok(cachedResult));
                return;
            }
        }
        catch (NumberParseException ex)
        {
            _log.Warning(ex, "Parsing failed for {PhoneNumber}", originalPhoneNumberStr);
            Sender.Tell(Result<PhoneNumberValidationResult, ShieldFailure>.Err(ShieldFailure.Generic(ex.Message, ex)));
            return;
        }

        try
        {
            PhoneNumberValidationResult result;
            if (!_phoneNumberUtil.IsValidNumber(parsedPhoneNumber))
            {
                PhoneNumberUtil.ValidationResult possibility =
                    _phoneNumberUtil.IsPossibleNumberWithReason(parsedPhoneNumber);
                ValidationFailureReason failureReason = MapPossibilityToFailureReason(possibility);
                string errorMessage = $"Invalid number. Reason: {possibility}";
                if (possibility == PhoneNumberUtil.ValidationResult.IS_POSSIBLE_LOCAL_ONLY &&
                    command.DefaultRegion == null && !originalPhoneNumberStr.StartsWith("+"))
                {
                    errorMessage += ". Consider providing a DefaultRegion if this is a local number.";
                }

                _log.Info("Validation failed for {PhoneNumber}: {Reason}", originalPhoneNumberStr, errorMessage);
                result = new PhoneNumberValidationResult(errorMessage, failureReason, e164FormatKey);
            }
            else
            {
                string? detectedRegion = _phoneNumberUtil.GetRegionCodeForNumber(parsedPhoneNumber);
                PhoneNumberType libType = _phoneNumberUtil.GetNumberType(parsedPhoneNumber);
                CustomPhoneNumberType customType = MapToCustomPhoneNumberType(libType);

                _log.Info("Successfully validated {PhoneNumber}. Region: {Region}, Type: {Type}",
                    originalPhoneNumberStr, detectedRegion, customType);
                result = new PhoneNumberValidationResult(e164FormatKey, detectedRegion, customType);
            }

            AddToCache(e164FormatKey, result);
            Sender.Tell(Result<PhoneNumberValidationResult, ShieldFailure>.Ok(result));
        }
        catch (Exception ex)
        {
            _log.Error(ex, "Unexpected error during validation for {PhoneNumber}", originalPhoneNumberStr);
            Sender.Tell(Result<PhoneNumberValidationResult, ShieldFailure>.Err(ShieldFailure.Generic(ex.Message, ex)));
        }
    }

    private CustomPhoneNumberType MapToCustomPhoneNumberType(PhoneNumbers.PhoneNumberType libType)
    {
        return libType switch
        {
            PhoneNumbers.PhoneNumberType.FIXED_LINE => CustomPhoneNumberType.FixedLine,
            PhoneNumbers.PhoneNumberType.MOBILE => CustomPhoneNumberType.Mobile,
            PhoneNumbers.PhoneNumberType.TOLL_FREE => CustomPhoneNumberType.TollFree,
            PhoneNumbers.PhoneNumberType.PREMIUM_RATE => CustomPhoneNumberType.PremiumRate,
            PhoneNumbers.PhoneNumberType.SHARED_COST => CustomPhoneNumberType.SharedCost,
            PhoneNumbers.PhoneNumberType.VOIP => CustomPhoneNumberType.Voip,
            PhoneNumbers.PhoneNumberType.PERSONAL_NUMBER => CustomPhoneNumberType.PersonalNumber,
            PhoneNumbers.PhoneNumberType.PAGER => CustomPhoneNumberType.Pager,
            PhoneNumbers.PhoneNumberType.UAN => CustomPhoneNumberType.Uan,
            PhoneNumbers.PhoneNumberType.VOICEMAIL => CustomPhoneNumberType.Voicemail,
            PhoneNumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE => CustomPhoneNumberType.FixedLineOrMobile,
            _ => CustomPhoneNumberType.Unknown,
        };
    }

    private ValidationFailureReason MapPossibilityToFailureReason(PhoneNumberUtil.ValidationResult possibility)
    {
        return possibility switch
        {
            PhoneNumberUtil.ValidationResult.INVALID_COUNTRY_CODE => ValidationFailureReason.InvalidCountryCode,
            PhoneNumberUtil.ValidationResult.TOO_SHORT => ValidationFailureReason.TooShort,
            PhoneNumberUtil.ValidationResult.TOO_LONG => ValidationFailureReason.TooLong,
            PhoneNumberUtil.ValidationResult.IS_POSSIBLE_LOCAL_ONLY =>
                ValidationFailureReason.PossibleButNotCertain,
            _ => ValidationFailureReason.InvalidNumber
        };
    }

    private void AddToCache(string key, PhoneNumberValidationResult value)
    {
        if (string.IsNullOrEmpty(key)) return;

        if (_cache.Count >= _cacheCapacity)
        {
            string? lruKey = _lruTracker.First?.Value;
            if (lruKey != null)
            {
                _cache.Remove(lruKey);
                _lruTracker.RemoveFirst();
                _log.Debug("Cache capacity reached. Evicted: {EvictedKey}", lruKey);
            }
        }

        _cache[key] = value;
        _lruTracker.AddLast(key);
    }

    private void UpdateLru(string key)
    {
        if (!_cache.ContainsKey(key)) return;

        _lruTracker.Remove(key);
        _lruTracker.AddLast(key);
    }

    public static Props Build(int cacheCapacity = 1000) =>
        Props.Create(() => new PhoneNumberValidatorActor(cacheCapacity));
}