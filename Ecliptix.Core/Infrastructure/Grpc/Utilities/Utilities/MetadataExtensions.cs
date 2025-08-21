using Ecliptix.Domain.Utilities;
using Grpc.Core;

namespace Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;

public static class MetadataExtensions
{
    private const string ComponentNotFoundFormat = "Component by {0} not found in metadata";

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