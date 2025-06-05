using Ecliptix.Domain;
using Ecliptix.Domain.Memberships.Failures;
using Microsoft.Extensions.Localization;

namespace Ecliptix.Core.Resources;

public class VerificationFlowLocalizer : ILocalizationProvider
{
    private readonly IStringLocalizer<VerificationFlowResource> _localizer;

    public VerificationFlowLocalizer(IStringLocalizer<VerificationFlowResource> localizer)
    {
        _localizer = localizer;
        var r = _localizer[VerificationFlowMessageKeys.InvalidCredentials];
    }

    public string GetString(string key)
    {
        return _localizer[key].Value;
    }
}