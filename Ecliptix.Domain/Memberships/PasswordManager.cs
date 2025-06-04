using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Utilities;

namespace Ecliptix.Domain.Memberships;

public sealed class PasswordManager
{
    private const int DefaultSaltSize = 16;
    private const int DefaultIterations = 600_000;
    private const char HashSeparator = ':';

    private static readonly Regex LowercaseRegex = new("[a-z]", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex UppercaseRegex = new("[A-Z]", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex DigitRegex = new(@"\d", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex AlphanumericOnlyRegex =
        new("^[a-zA-Z0-9]*$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private readonly int _iterations;
    private readonly HashAlgorithmName _hashAlgorithmName;
    private readonly int _saltSize;

    private PasswordManager(int iterations, HashAlgorithmName hashAlgorithmName, int saltSize)
    {
        _iterations = iterations;
        _hashAlgorithmName = hashAlgorithmName;
        _saltSize = saltSize;
    }

    public static Result<PasswordManager, VerificationFlowFailure> Create(
        int iterations = DefaultIterations,
        HashAlgorithmName? hashAlgorithmName = null,
        int saltSize = DefaultSaltSize)
    {
        if (iterations <= 0)
        {
            return Result<PasswordManager, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Validation(VerificationFlowMessageKeys.PasswordManagerConfigIterations));
        }

        if (saltSize <= 0)
        {
            return Result<PasswordManager, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Validation(VerificationFlowMessageKeys.PasswordManagerConfigSaltSize));
        }

        HashAlgorithmName effectiveHashAlgorithm = hashAlgorithmName ?? HashAlgorithmName.SHA256;

        if (effectiveHashAlgorithm != HashAlgorithmName.SHA1 &&
            effectiveHashAlgorithm != HashAlgorithmName.SHA256 &&
            effectiveHashAlgorithm != HashAlgorithmName.SHA384 &&
            effectiveHashAlgorithm != HashAlgorithmName.SHA512)
        {
            return Result<PasswordManager, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Validation(VerificationFlowMessageKeys.PasswordManagerConfigHashAlgorithm));
        }

        return Result<PasswordManager, VerificationFlowFailure>.Ok(new PasswordManager(iterations,
            effectiveHashAlgorithm,
            saltSize));
    }

    public Result<Unit, VerificationFlowFailure> CheckPasswordCompliance(
        string password,
        PasswordPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy, nameof(policy));

        List<Func<(string Password, PasswordPolicy Policy), Option<string>>> validationRules =
        [
            ValidatePasswordNotEmpty,
            ValidatePasswordLength,
            ValidateLowercaseRequirement,
            ValidateUppercaseRequirement,
            ValidateDigitRequirement,
            ValidateSpecialCharRequirement,
            ValidateAllowedCharsOnly
        ];

        List<string?> validationErrors = validationRules
            .Select(rule => rule((password, policy)))
            .Where(result => result.HasValue)
            .Select(result => result.Value)
            .ToList();

        return validationErrors.Count != 0
            ? Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Validation(VerificationFlowMessageKeys.PasswordComplexityRequirements))
            : Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
    }

    private static Option<string> ValidatePasswordNotEmpty((string Password, PasswordPolicy Policy) input) =>
        string.IsNullOrEmpty(input.Password)
            ? Option<string>.Some(VerificationFlowMessageKeys.PasswordEmpty)
            : Option<string>.None;

    private static Option<string> ValidatePasswordLength((string Password, PasswordPolicy Policy) input) =>
        !string.IsNullOrEmpty(input.Password) && input.Password.Length < input.Policy.MinLength
            ? Option<string>.Some(VerificationFlowMessageKeys.PasswordTooShort)
            : Option<string>.None;

    private static Option<string> ValidateLowercaseRequirement((string Password, PasswordPolicy Policy) input) =>
        !string.IsNullOrEmpty(input.Password) &&
        input.Policy.RequireLowercase &&
        !LowercaseRegex.IsMatch(input.Password)
            ? Option<string>.Some(VerificationFlowMessageKeys.PasswordMissingLowercase)
            : Option<string>.None;

    private static Option<string> ValidateUppercaseRequirement((string Password, PasswordPolicy Policy) input) =>
        !string.IsNullOrEmpty(input.Password) &&
        input.Policy.RequireUppercase &&
        !UppercaseRegex.IsMatch(input.Password)
            ? Option<string>.Some(VerificationFlowMessageKeys.PasswordMissingUppercase)
            : Option<string>.None;

    private static Option<string> ValidateDigitRequirement((string Password, PasswordPolicy Policy) input) =>
        !string.IsNullOrEmpty(input.Password) &&
        input.Policy.RequireDigit &&
        !DigitRegex.IsMatch(input.Password)
            ? Option<string>.Some(VerificationFlowMessageKeys.PasswordMissingDigit)
            : Option<string>.None;

    private static Option<string> ValidateSpecialCharRequirement((string Password, PasswordPolicy Policy) input)
    {
        if (string.IsNullOrEmpty(input.Password) ||
            !input.Policy.RequireSpecialChar ||
            string.IsNullOrEmpty(input.Policy.AllowedSpecialChars))
        {
            return Option<string>.None;
        }

        string specialCharPattern = $"[{Regex.Escape(input.Policy.AllowedSpecialChars)}]";
        return !Regex.IsMatch(input.Password, specialCharPattern)
            ? Option<string>.Some(VerificationFlowMessageKeys.PasswordMissingSpecialChar)
            : Option<string>.None;
    }

    private static Option<string> ValidateAllowedCharsOnly((string Password, PasswordPolicy Policy) input)
    {
        if (string.IsNullOrEmpty(input.Password) || !input.Policy.EnforceAllowedCharsOnly)
        {
            return Option<string>.None;
        }

        if (!string.IsNullOrEmpty(input.Policy.AllowedSpecialChars))
        {
            string allAllowedCharsPattern = $"^[a-zA-Z0-9{Regex.Escape(input.Policy.AllowedSpecialChars)}]*$";
            return !Regex.IsMatch(input.Password, allAllowedCharsPattern)
                ? Option<string>.Some(VerificationFlowMessageKeys.PasswordInvalidChars)
                : Option<string>.None;
        }

        return !AlphanumericOnlyRegex.IsMatch(input.Password)
            ? Option<string>.Some(VerificationFlowMessageKeys.PasswordInvalidChars)
            : Option<string>.None;
    }

    private Result<byte[], VerificationFlowFailure> GenerateSalt()
    {
        byte[] salt = new byte[_saltSize];
        using RandomNumberGenerator rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);
        return Result<byte[], VerificationFlowFailure>.Ok(salt);
    }

    public Result<string, VerificationFlowFailure> HashPassword(string password)
    {
        if (string.IsNullOrEmpty(password))
        {
            return Result<string, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Validation(VerificationFlowMessageKeys.PasswordHashInputEmpty));
        }

        return GenerateSalt()
            .Bind(salt => CreatePbkdf2Hash(password, salt))
            .Bind(hashResult => FormatHashWithSalt(hashResult.Salt, hashResult.Hash));
    }

    public Result<Unit, VerificationFlowFailure> VerifyPassword(string password, string hashedPasswordWithSalt)
    {
        if (string.IsNullOrEmpty(password))
        {
            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Validation(VerificationFlowMessageKeys.PasswordVerifyInputEmpty));
        }

        if (string.IsNullOrEmpty(hashedPasswordWithSalt))
        {
            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Validation(VerificationFlowMessageKeys.PasswordVerifyStoredHashEmpty));
        }

        return ParseStoredHash(hashedPasswordWithSalt)
            .Bind(parsed => ValidateSaltSize(parsed.Salt).Map(_ => parsed))
            .Bind(parsed => ValidateHashSize(parsed.Hash).Map(_ => parsed))
            .Bind(parsed => VerifyPasswordHash(password, parsed.Salt, parsed.Hash));
    }

    private static Result<(byte[] Salt, byte[] Hash), VerificationFlowFailure> ParseStoredHash(string hashedPasswordWithSalt)
    {
        string[] parts = hashedPasswordWithSalt.Split(HashSeparator);
        if (parts.Length != 2)
        {
            return Result<(byte[], byte[]), VerificationFlowFailure>.Err(
                VerificationFlowFailure.Validation(VerificationFlowMessageKeys.PasswordVerifyInvalidFormat));
        }

        return ParseBase64Component(parts[0])
            .Bind(salt => ParseBase64Component(parts[1]).Map(hash => (salt, hash)));
    }

    private static Result<byte[], VerificationFlowFailure> ParseBase64Component(string base64String)
    {
        if (Convert.TryFromBase64String(base64String, new Span<byte>(new byte[base64String.Length]),
                out int bytesWritten))
        {
            byte[] result = new byte[bytesWritten];
            Convert.TryFromBase64String(base64String, result, out _);
            return Result<byte[], VerificationFlowFailure>.Ok(result);
        }

        return Result<byte[], VerificationFlowFailure>.Err(
            VerificationFlowFailure.Validation(VerificationFlowMessageKeys.PasswordVerifyBase64Error));
    }

    private Result<Unit, VerificationFlowFailure> ValidateSaltSize(byte[] salt)
    {
        return salt.Length == _saltSize
            ? Result<Unit, VerificationFlowFailure>.Ok(Unit.Value)
            : Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Validation(VerificationFlowMessageKeys.PasswordVerifySaltSizeMismatch));
    }

    private Result<Unit, VerificationFlowFailure> ValidateHashSize(byte[] hash)
    {
        int expectedHashSize = GetHashSizeForAlgorithm(_hashAlgorithmName);
        return hash.Length == expectedHashSize
            ? Result<Unit, VerificationFlowFailure>.Ok(Unit.Value)
            : Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Validation(VerificationFlowMessageKeys.PasswordVerifyHashSizeMismatch));
    }

    private Result<(byte[] Salt, byte[] Hash), VerificationFlowFailure> CreatePbkdf2Hash(string password, byte[] salt)
    {
        using Rfc2898DeriveBytes pbkdf2 = new(password, salt, _iterations, _hashAlgorithmName);
        byte[] hash = pbkdf2.GetBytes(GetHashSizeForAlgorithm(_hashAlgorithmName));
        return Result<(byte[], byte[]), VerificationFlowFailure>.Ok((salt, hash));
    }

    private Result<Unit, VerificationFlowFailure> VerifyPasswordHash(string password, byte[] salt, byte[] storedHash)
    {
        return CreatePbkdf2Hash(password, salt)
            .Bind(hashResult => CompareHashes(hashResult.Hash, storedHash));
    }

    private static Result<Unit, VerificationFlowFailure> CompareHashes(byte[] computedHash, byte[] storedHash)
    {
        return CryptographicOperations.FixedTimeEquals(computedHash, storedHash)
            ? Result<Unit, VerificationFlowFailure>.Ok(Unit.Value)
            : Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Validation(VerificationFlowMessageKeys.PasswordVerifyMismatch));
    }

    private static Result<string, VerificationFlowFailure> FormatHashWithSalt(byte[] salt, byte[] hash)
    {
        string formatted = $"{Convert.ToBase64String(salt)}{HashSeparator}{Convert.ToBase64String(hash)}";
        return Result<string, VerificationFlowFailure>.Ok(formatted);
    }

    private static int GetHashSizeForAlgorithm(HashAlgorithmName algName)
    {
        return algName.Name switch
        {
            _ when algName.Name == HashAlgorithmName.SHA1.Name => 20,
            _ when algName.Name == HashAlgorithmName.SHA256.Name => 32,
            _ when algName.Name == HashAlgorithmName.SHA384.Name => 48,
            _ when algName.Name == HashAlgorithmName.SHA512.Name => 64,
            _ => throw new NotSupportedException(
                $"Hash size not defined for algorithm '{algName.Name}'. This indicates an internal configuration issue and should have been caught during PasswordManager creation.")
        };
    }
}