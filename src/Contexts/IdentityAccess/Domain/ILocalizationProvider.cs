namespace Ecliptix.IdentityAccess.Domain;

public interface ILocalizationProvider
{
    string Localize(string key, string cultureName);

    string Localize(string key);
}
