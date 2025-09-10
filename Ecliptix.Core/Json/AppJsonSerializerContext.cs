using System.Text.Json;
using System.Text.Json.Serialization;
using Ecliptix.Core.Middleware;
using Ecliptix.Core.Middleware.Models;

namespace Ecliptix.Core.Json;

[JsonSourceGenerationOptions(
    WriteIndented = false,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    GenerationMode = JsonSourceGenerationMode.Default,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(BlockInfo))]
[JsonSerializable(typeof(ThrottleInfo))]
[JsonSerializable(typeof(HealthMetricsResponse))]
[JsonSerializable(typeof(ProtocolMetrics))]
[JsonSerializable(typeof(HealthStatus))]
[JsonSerializable(typeof(ErrorResponse))]
[JsonSerializable(typeof(long))]
public partial class AppJsonSerializerContext : JsonSerializerContext
{
}

public record HealthMetricsResponse(
    HealthStatus Health,
    ProtocolMetrics Protocol,
    DateTime Timestamp);

public record HealthStatus(
    string Status,
    string? Description,
    Dictionary<string, object>? Data);

public record ProtocolMetrics(
    string Status,
    string Message,
    string Note);

public record ErrorResponse(string Message);