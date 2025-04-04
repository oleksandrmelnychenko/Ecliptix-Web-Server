using Grpc.Core;

namespace Ecliptix.Domain.Utilities;

public static class MetadataExtensions {
    public static string? GetValueOrDefault(this Metadata metadata, string key) => metadata.Where(entry => entry.Key.Equals(key, StringComparison.OrdinalIgnoreCase)).Select(entry => entry.Value).FirstOrDefault();
    public static void ThrowIfNull<T>(this T obj, string errorMessage) where T : class? {
        if (obj == null) {
            throw new ArgumentNullException(errorMessage);
        }
    }
}


