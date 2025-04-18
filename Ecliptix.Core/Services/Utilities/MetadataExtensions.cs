using Ecliptix.Core.Protocol.Utilities;
using Grpc.Core;

namespace Ecliptix.Core.Services.Utilities;

public static class MetadataExtensions
{
    public const string KeyExchangeContextType = "KeyExchangeContextType";

    public const string ComponentNotFoundFormat = "Component by {0} not found in metadata";

    public static Result<string, MetaDataSystemFailure> GetValueAsResult(this Metadata metadata, string key)
    {
        string? value = metadata
            .Where(entry => entry.Key.Equals(key, StringComparison.OrdinalIgnoreCase))
            .Select(entry => entry.Value)
            .FirstOrDefault();

        return !string.IsNullOrEmpty(value)
            ? Result<string, MetaDataSystemFailure>.Ok(value)
            : Result<string, MetaDataSystemFailure>.Err(
                MetaDataSystemFailure.ComponentNotFound(string.Format(ComponentNotFoundFormat, key)));
    }
}