using System.Globalization;
using System.Resources;
using Ecliptix.Domain;

namespace Ecliptix.Core.Resources;

public class VerificationFlowLocalizer : ILocalizationProvider
{
    private readonly CultureInfo _defaultSystemCultureInfo = CultureInfo.GetCultureInfo("en-US");

    private readonly ResourceManager _resourceManager = new(
        "Ecliptix.Core.Resources.VerificationFlowRes",
        typeof(VerificationFlowLocalizer).Assembly);

    public string Localize(string key, string cultureName)
    {
        CultureInfo culture = CultureInfo.GetCultureInfo(cultureName);

        string? localizedString = _resourceManager.GetString(key, culture);
        if (string.IsNullOrEmpty(localizedString)) localizedString = key;

        return localizedString;
    }

    public string Localize(string key)
    {
        string? localizedString = _resourceManager.GetString(key, _defaultSystemCultureInfo);
        if (string.IsNullOrEmpty(localizedString)) localizedString = key;

        return localizedString;
    }
}