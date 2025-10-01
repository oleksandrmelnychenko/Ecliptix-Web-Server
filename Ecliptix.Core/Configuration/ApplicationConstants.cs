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
        public const string MasterKeySharePersistorActor = "MasterKeySharePersistorActor";
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
        [Obsolete("Use TimeoutConfiguration.Actor.SupervisionTimeout")]
        public const int SupervisionTimeoutMinutes = 5;
        [Obsolete("Use TimeoutConfiguration.Actor.StreamingTimeout")]
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

    public static class LogMessages
    {
        public const string StartingApplication = "Starting Ecliptix application host";
        public const string ApplicationTerminatedUnexpectedly = "Ecliptix application host terminated unexpectedly";
        public const string ShuttingDownApplication = "Shutting down Ecliptix application host";
        public const string ActorSystemStarted = "Actor system hosted service started - {ActorSystemName}";
        public const string ActorSystemInitiatingShutdown = "Actor system hosted service initiating graceful shutdown...";
        public const string ActorSystemShutdownCompleted = "Actor system coordinated shutdown completed successfully";
        public const string ShutdownCancelledForcing = "Shutdown was cancelled by host, forcing actor system termination";
        public const string ErrorDuringShutdownForcing = "Error during actor system shutdown, forcing termination";
        public const string ActorSystemShutdownComplete = "Actor system hosted service shutdown complete";
        public const string PhaseStopAcceptingConnections = "Phase: Stop accepting new connections";
        public const string PhaseDrainingActiveRequests = "Phase: Draining active requests";
        public const string ActiveRequestDrainingCompleted = "Active request draining completed";
        public const string PhaseCleanupResources = "Phase: Cleaning up application resources";
        public const string RateLimitExceeded = "Rate limit exceeded for {IpAddress}";
    }

    public static class HttpHeaders
    {
        public const string UserAgent = "User-Agent";
        public const string ConnectId = "X-Connect-Id";
    }

    public static class DiagnosticContext
    {
        public const string RequestHost = "RequestHost";
        public const string UserAgent = "UserAgent";
        public const string Protocol = "Protocol";
        public const string ConnectId = "ConnectId";
        public const string RequestSize = "RequestSize";
    }

    public static class StatusMessages
    {
        public const string Success = "Success";
        public const string ServerRunning = "Server is up and running";
    }

    public static class FallbackValues
    {
        public const string UnknownIpAddress = "unknown";
    }

    public static class ConfigurationKeys
    {
        public const string KeyExchangeContextTypeKey = "KeyExchangeContextTypeKey";
        public const string KeyExchangeContextTypeValue = "KeyExchangeContextTypeValue";
    }
}