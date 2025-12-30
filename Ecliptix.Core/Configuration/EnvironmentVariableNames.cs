namespace Ecliptix.Core.Configuration;

public static class EnvironmentVariableNames
{
    public const string MigrateOnly = "MIGRATE_ONLY";
    public const string OtelExporterOtlpEndpoint = "OTEL_EXPORTER_OTLP_ENDPOINT";
    public const string OtelConsoleExporterEnabled = "OTEL_CONSOLE_EXPORTER_ENABLED";
    public const string PodIp = "POD_IP";
    public const string AkkaPort = "AKKA_PORT";
}
