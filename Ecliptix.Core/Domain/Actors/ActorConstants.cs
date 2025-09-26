namespace Ecliptix.Core.Domain.Actors;

public static class ActorConstants
{
    public static class ActorNamePrefixes
    {
        public const string Connect = "connect-";
    }

    public static class Supervision
    {
        public const int MaxRetries = 3;
        public const int TimeoutMinutes = 5;
    }

    public static class Recovery
    {
        public const int MaxRetries = 3;
        public const string RetryTimerKey = "recovery-retry";
    }

    public static class Timeouts
    {
        public const int IdleTimeoutMinutes = 1;
    }

    public static class Constants
    {
        public const int SnapshotInterval = 100;
        public const int SnapshotModulus = 10;
        public const int SnapshotMinuteMultiplier = 5;
        public const uint NonceCounterWarningThreshold = 1000;
        public const int IdentityKeySize = 10;
        public const int RatchetMessagesInterval10 = 10;
        public const int RatchetMessagesInterval20 = 20;
        public const int MaxChainAge6Hours = 6;
        public const int MaxChainAge5Minutes = 5;
        public const int MaxMessagesWithoutRatchet200 = 200;
        public const int MaxMessagesWithoutRatchet100 = 100;
        public const int Zero = 0;
    }

    public static class Validation
    {
        public const uint MaxChainIndex = 10_000_000;
        public const int ExpectedDhKeySize = 32;
    }

    public static class LogMessages
    {
        public const string SupervisedActorTerminated = "Supervised session actor {ActorPath} has terminated. Its resources are released";
        public const string ProtocolCleanupTriggered = "Triggered protocol cleanup for ConnectId {ConnectId} due to session expiration";
        public const string InitializationFailed = "Protocol connect actor failed during initialization. Stopping to prevent further issues";
        public const string TimeoutEncountered = "Protocol connect actor encountered timeout. Restarting";
        public const string AuthorizationFailure = "Protocol connect actor encountered authorization failure. Stopping";
        public const string InvalidArguments = "Protocol connect actor failed with invalid arguments. Stopping to prevent repeated failures";
        public const string CryptographicError = "Protocol connect actor encountered cryptographic error. Restarting";
        public const string InvalidOperation = "Protocol connect actor encountered invalid operation. Restarting";
        public const string IoError = "Protocol connect actor encountered IO error. Restarting";
        public const string NetworkError = "Protocol connect actor encountered network error. Restarting";
        public const string OutOfMemory = "Protocol connect actor out of memory. Escalating to parent";
        public const string StackOverflow = "Protocol connect actor stack overflow. Escalating to parent";
        public const string UnhandledException = "Protocol connect actor encountered unhandled exception of type {ExceptionType}. Stopping to prevent cascading failures";

        public const string RecoveryCompleted = "[RecoveryCompleted] Recovery finished for actor {ActorName}";
        public const string NoSessionState = "[RecoveryCompleted] No previous session state found for connectId {ConnectId}";
        public const string FinalSnapshotSaved = "Final snapshot saved successfully. Initiating cleanup operation.";

        public const string SessionRestorationPrevented = "SERVER_STREAMING session restoration prevented - fresh handshake required";
        public const string StateIntegrityValidationFailed = "State integrity validation failed: {Error}. Clearing session.";
        public const string LiveConnectionCleared = "Live system connection was cleared (likely due to fresh handshake detection). Clearing actor state.";
        public const string SessionRestored = "Session restored - ConnectId: {ConnectId}, Sending: {SendingIdx}, Receiving: {ReceivingIdx}, LastPersist: {LastPersist}";

        public const string SelectingRatchetConfig = "[ACTOR] Selecting ratchet config for exchange type: {ExchangeType}";
        public const string UsingExistingSession = "[HandleInitialKeyExchange] Using existing recovered session for connectId {ConnectId}, type: {ExchangeType}";
        public const string SystemDetectedFreshHandshake = "[HandleInitialKeyExchange] System detected fresh handshake - clearing actor state";
        public const string CreatingNewSession = "[HandleInitialKeyExchange] Creating new session for connectId {ConnectId}, type: {ExchangeType}";
        public const string CreatedProtocolWithInterval = "[ACTOR] Created protocol with DH interval {DhInterval} for type {ExchangeType}";
    }

    public static class ErrorMessages
    {
        public const string FailedToCreateActor = "Failed to create actor for connectId: ";
        public const string Cryptographic = "cryptographic";
        public const string RatchetStateMissing = "Ratchet state missing";
        public const string RootKeyMissing = "Root key missing from recovered state";
        public const string ChainKeysMissing = "Chain keys missing from recovered state";
        public const string NonceCounterOverflow = "Nonce counter near overflow";
    }
}