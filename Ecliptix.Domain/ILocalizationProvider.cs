namespace Ecliptix.Domain;

public interface ILocalizationProvider
{
    string GetString(string key);
}