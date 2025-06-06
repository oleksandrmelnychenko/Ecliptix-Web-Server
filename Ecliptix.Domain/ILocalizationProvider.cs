using Ecliptix.Domain.Utilities;

namespace Ecliptix.Domain;

public interface ILocalizationProvider
{
    string Localize(string key);
}