using Ecliptix.Domain.Utilities;

namespace Ecliptix.Domain;

public interface ILocalizationProvider
{
    string Localize(string key, string cultureName);
    
    string Localize(string key);
}