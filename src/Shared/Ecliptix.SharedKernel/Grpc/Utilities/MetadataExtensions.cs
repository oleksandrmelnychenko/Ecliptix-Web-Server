using Grpc.Core;

namespace Ecliptix.SharedKernel.Grpc.Utilities;

public static class MetadataExtensions
{
    private const string ComponentNotFoundFormat = "Component by {0} not found in metadata";

    public static Result<string, MetaDataSystemFailure> GetValueAsResult(this Metadata metadata, string key)
    {
        foreach (Metadata.Entry entry in metadata)
        {
            if (entry.Key.Equals(key, StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrEmpty(entry.Value))
            {
                return Result<string, MetaDataSystemFailure>.Ok(entry.Value);
            }
        }

        return Result<string, MetaDataSystemFailure>.Err(
            MetaDataSystemFailure.ComponentNotFound(string.Format(ComponentNotFoundFormat, key)));
    }
}
