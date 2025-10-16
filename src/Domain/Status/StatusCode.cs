using System.Collections.Frozen;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Ecliptix.Domain.Status;

public readonly record struct StatusCode(string Code)
{
    private static readonly Regex CodePattern = new("^[a-z][a-z0-9_-]{1,30}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static IReadOnlySet<string> _allowed = FrozenSet<string>.Empty;

    public string Code { get; init; } = Normalize(Code);

    public static IReadOnlySet<string> Allowed => _allowed;

    public static StatusCode Create(string code) => new(code);

    public static StatusCode Parse(string code) => new(code);

    public static bool TryParse(string? code, out StatusCode status)
    {
        if (string.IsNullOrWhiteSpace(code))
        {
            status = default;
            return false;
        }

        string normalized;
        try
        {
            normalized = Normalize(code, throwIfUnknown: false);
        }
        catch (ArgumentException)
        {
            status = default;
            return false;
        }

        if (_allowed.Count > 0 && !_allowed.Contains(normalized))
        {
            status = default;
            return false;
        }

        status = new StatusCode(normalized);
        return true;
    }

    internal static void SetAllowedCodes(IEnumerable<string> allowed)
    {
        if (allowed is null)
        {
            throw new ArgumentNullException(nameof(allowed));
        }

        _allowed = allowed.ToFrozenSet(StringComparer.Ordinal);
    }

    public override string ToString() => Code;

    private static string Normalize(string code) => Normalize(code, throwIfUnknown: true);

    private static string Normalize(string code, bool throwIfUnknown)
    {
        StatusRegistry.EnsureInitialized();

        if (string.IsNullOrWhiteSpace(code))
        {
            throw new ArgumentException("Status code cannot be null or whitespace.", nameof(code));
        }

        string normalized = code.Trim().ToLowerInvariant();

        if (!CodePattern.IsMatch(normalized))
        {
            throw new ArgumentException(
                $"Status code '{code}' must match pattern '{CodePattern.ToString()}' (lowercase alphanumeric, hyphen or underscore, length 2-31).",
                nameof(code));
        }

        if (_allowed.Count > 0 && !_allowed.Contains(normalized))
        {
            if (throwIfUnknown)
            {
                throw new ArgumentOutOfRangeException(nameof(code), normalized, "Status code is not registered.");
            }

            return normalized;
        }

        return normalized;
    }

    public sealed class JsonConverter : JsonConverter<StatusCode>
    {
        public override StatusCode Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType != JsonTokenType.String)
            {
                throw new JsonException("Status code must be encoded as a JSON string.");
            }

            string? value = reader.GetString();
            if (!TryParse(value, out StatusCode status))
            {
                throw new JsonException($"Unknown status code '{value}'.");
            }

            return status;
        }

        public override void Write(Utf8JsonWriter writer, StatusCode value, JsonSerializerOptions options)
        {
            writer.WriteStringValue(value.Code);
        }
    }
}
