using System.Globalization;
using System.Resources;
using Ecliptix.Domain;

namespace Ecliptix.Core.Resources;

public class VerificationFlowLocalizer : ILocalizationProvider
{
    private readonly ResourceManager _resourceManager = new(
        "Ecliptix.Core.Resources.VerificationFlowRes",
        typeof(VerificationFlowLocalizer).Assembly);

    private string _defaultCultureName = "en-US";

    public string Localize(string key)
    {
        CultureInfo culture = CultureInfo.GetCultureInfo(_defaultCultureName);

        string? localizedString = _resourceManager.GetString(key, culture);
        if (string.IsNullOrEmpty(localizedString))
        {
            localizedString = key;
        }

        return localizedString;
    }

    public void Initialize(string cultureName) =>
        _defaultCultureName = cultureName;
}