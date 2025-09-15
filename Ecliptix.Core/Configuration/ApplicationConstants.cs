namespace Ecliptix.Core.Configuration;

public static class ApplicationConstants
{
    public static class ActorSystem
    {
        public const string SystemName = "EcliptixProtocolSystemActor";
        public const string ConfigFileName = "akka.conf";
    }

    public static class ActorNames
    {
        public const string ProtocolSystem = "ProtocolSystem";
        public const string AppDevicePersistor = "AppDevicePersistor";
        public const string VerificationFlowPersistorActor = "VerificationFlowPersistorActor";
        public const string VerificationFlowManagerActor = "VerificationFlowManagerActor";
        public const string MembershipPersistorActor = "MembershipPersistorActor";
        public const string MembershipActor = "MembershipActor";
        public const string AuthContextPersistorActor = "AuthContextPersistorActor";
        public const string AuthenticationStateManager = "AuthenticationStateManager";
    }

    public static class Endpoints
    {
        public const string Health = "/health";
        public const string Metrics = "/metrics";
        public const string Root = "/";
    }

    public static class Localization
    {
        public const string ResourcesPath = "Resources";
        public const string DefaultCulture = "en-us";
        public const string UkrainianCulture = "uk-ua";
    }

    public static class HealthChecks
    {
        public const string ProtocolHealth = "protocol_health";
        public const string VerificationFlowHealth = "verification_flow_health";
        public const string DatabaseHealth = "database_health";
    }

    public static class Configuration
    {
        public const string TwilioSettings = "TwilioSettings";
        public const string OpaqueProtocolSecretKeySeed = "OpaqueProtocol:SecretKeySeed";
        public const string SecurityKeys = "SecurityKeys";
    }

    public static class Logging
    {
        public const string HttpRequestTemplate = "HTTP {RequestMethod} {RequestPath} responded {StatusCode} in {Elapsed:0.0000} ms";
        public const string Environment = "Environment";
    }

    public static class ActorSystemTasks
    {
        public const string StopAcceptingNewConnections = "stop-accepting-new-connections";
        public const string DrainActiveRequests = "drain-active-requests";
        public const string CleanupResources = "cleanup-resources";
    }

    public static class Protocol
    {
        public const int SupervisionMaxRetries = 3;
        public const int SupervisionTimeoutMinutes = 5;
        public const int StreamingTimeoutMinutes = 6;
    }

    public static class Arrays
    {
        public const int FirstIndex = 0;
        public const int InitialValue = 0;
        public const int WindowResetValue = 0;
        public const int SingleMinute = 1;
        public const string DefaultCultureFallback = "en-US";
    }
}