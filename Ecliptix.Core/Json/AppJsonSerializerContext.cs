using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ecliptix.Core.Json;

[JsonSourceGenerationOptions(
    WriteIndented = false,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    GenerationMode = JsonSourceGenerationMode.Default,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(HealthMetricsResponse))]
[JsonSerializable(typeof(HealthStatus))]
[JsonSerializable(typeof(ErrorResponse))]
[JsonSerializable(typeof(long))]
public partial class AppJsonSerializerContext : JsonSerializerContext
{
}

public record HealthMetricsResponse(
    HealthStatus Health,
    DateTime Timestamp);

public record HealthStatus(
    string Status,
    string? Description,
    Dictionary<string, object>? Data);

public record ErrorResponse(string Message);