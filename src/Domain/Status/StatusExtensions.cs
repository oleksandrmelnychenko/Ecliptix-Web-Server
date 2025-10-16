using System.Collections.Generic;

namespace Ecliptix.Domain.Status;

public static class StatusExtensions
{
    public static bool IsOneOf(this StatusCode status, params string[] codes)
    {
        if (codes is null || codes.Length == 0)
        {
            return false;
        }

        foreach (string code in codes)
        {
            if (code is not null && string.Equals(status.Code, code, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    public static string ToDisplayLabel(this StatusCode status, string? culture)
    {
        StatusRegistry.EnsureInitialized();

        string cultureKey = NormalizeCulture(culture);

        return cultureKey switch
        {
            "uk" or "uk-ua" => ResolveLabel(Domain.StatusLabels.Uk, status),
            _ => ResolveLabel(Domain.StatusLabels.En, status)
        };
    }

    public static bool IsTerminal(this StatusCode status)
    {
        return status.IsOneOf(
            StatusCatalog.Common.Expired,
            StatusCatalog.Common.Archived,
            StatusCatalog.Common.Failed);
    }

    private static string ResolveLabel(IReadOnlyDictionary<string, string> labels, StatusCode status)
    {
        return labels.TryGetValue(status.Code, out string? label)
            ? label
            : status.Code;
    }

    private static string NormalizeCulture(string? culture)
    {
        if (string.IsNullOrWhiteSpace(culture))
        {
            return "en";
        }

        return culture.Trim().ToLowerInvariant();
    }
}
