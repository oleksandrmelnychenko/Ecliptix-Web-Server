using System.Collections.Frozen;
using Ecliptix.Domain.Status;

namespace Ecliptix.Domain;

public static class StatusRegistry
{
    private static readonly Lock Gate = new();
    private static bool _initialized;

    public static void EnsureInitialized()
    {
        lock (Gate)
        {
            if (_initialized)
            {
                return;
            }
        }

        lock (Gate)
        {
            if (_initialized)
            {
                return;
            }

            InitializeCore();
            _initialized = true;
        }
    }

    private static void InitializeCore()
    {
        IReadOnlyList<string> codes = StatusCatalog.AllCodes.Distinct(StringComparer.Ordinal)
            .OrderBy(code => code, StringComparer.Ordinal)
            .ToList();

        IReadOnlySet<string> allowed = codes.Count == 0
            ? FrozenSet<string>.Empty
            : codes.ToFrozenSet(StringComparer.Ordinal);

        StatusCode.SetAllowedCodes(allowed);

        ValidateLabels(codes, Domain.StatusLabels.En, "en");
        ValidateLabels(codes, Domain.StatusLabels.Uk, "uk");
    }

    private static void ValidateLabels(IEnumerable<string> codes, IReadOnlyDictionary<string, string> labels, string culture)
    {
        string[] missing = codes.Where(code => !labels.ContainsKey(code)).ToArray();

        if (missing.Length > 0)
        {
            throw new InvalidOperationException(
                $"Missing {culture} labels for status codes: {string.Join(", ", missing)}");
        }
    }
}
