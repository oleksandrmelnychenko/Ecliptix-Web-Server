namespace Ecliptix.Security.Opaque.Constants;

public static class OpaqueServerConstants
{
    public static class ErrorMessages
    {
        public const string ServiceNotInitialized = "OPAQUE server service not initialized";
        public const string ServiceDisposed = "OPAQUE server service has been disposed";
        public const string InitializationException = "OPAQUE initialization exception occurred";
        public const string CryptographicException = "Cryptographic exception occurred";
        public const string StorageException = "Storage exception occurred";

        public const string FailedToCreateServer = "Failed to create server";
        public const string FailedToCreateCredentialStore = "Failed to create credential store";
        public const string FailedToCreateServerState = "Failed to create server state";
        public const string FailedToCreateRegistrationResponse = "Failed to create registration response";
        public const string FailedToGenerateKE2 = "Failed to generate KE2";
        public const string FailedToFinishAuthentication = "Failed to finish authentication";
        public const string FailedToStoreCredentials = "Failed to store credentials for user";
        public const string FailedToRetrieveCredentials = "Failed to retrieve credentials for user";
    }

    public static class ValidationMessages
    {
        public const string RegistrationRequestDataRequired = "Registration request data is required";
        public const string KE1DataRequired = "KE1 data is required";
        public const string KE3DataRequired = "KE3 data is required";
        public const string StoredCredentialsRequired = "Stored credentials are required";
        public const string UserIdRequired = "User ID is required";
        public const string CredentialsRequired = "Credentials are required";
        public const string NoActiveServerState = "No active server state - call GenerateKE2 first";
    }

    public static class LogMessages
    {
        public const string ServerInitialized = "OPAQUE server service v{Version} initialized successfully";
        public const string ServerDisposed = "OPAQUE server service disposed";
        public const string InitializationFailed = "OPAQUE server initialization failed: {Error}";
    }
}