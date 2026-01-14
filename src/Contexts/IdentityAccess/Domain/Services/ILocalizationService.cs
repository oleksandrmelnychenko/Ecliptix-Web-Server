namespace Ecliptix.IdentityAccess.Domain.Services;

public interface ILocalizationService
{
    string Localize(string key, string cultureName);
}
