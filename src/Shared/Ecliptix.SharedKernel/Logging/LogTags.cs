namespace Ecliptix.SharedKernel.Logging;

/// <summary>
/// Centralized log message tags for consistent logging across the application.
/// </summary>
public static class LogTags
{
    public static class Protocol
    {
        public const string Init = "[PROTOCOL-INIT]";
        public const string General = "[PROTOCOL]";
        public const string GetState = "[GET-PROTOCOL-STATE]";
        public const string GetKyberKey = "[GET-KYBER-KEY]";
        public const string HandshakeKyber = "[HANDSHAKE-KYBER]";
        public const string AuthHandshake = "[AUTH-HANDSHAKE]";
    }

    public static class Recovery
    {
        public const string General = "[RECOVERY]";
        public const string Membership = "[MEMBERSHIP-RECOVERY]";
    }

    public static class PasswordRecovery
    {
        public const string Init = "[PASSWORD-RECOVERY-INIT]";
        public const string General = "[PASSWORD-RECOVERY]";
        public const string Complete = "[PASSWORD-RECOVERY-COMPLETE]";
        public const string Validation = "[PASSWORD-RECOVERY-VALIDATION]";
        public const string Expire = "[PASSWORD-RECOVERY-EXPIRE]";
        public const string Initiate = "[INITIATE-PASSWORD-RECOVERY]";
    }

    public static class Session
    {
        public const string ServerRestore = "[SERVER-RESTORE]";
        public const string Refresh = "[SESSION-REFRESH]";
        public const string FreshHandshake = "[FRESH-HANDSHAKE]";
    }

    public static class State
    {
        public const string ExportFailed = "[STATE-EXPORT-FAILED]";
        public const string ChainIndices = "[CHAIN-INDICES]";
    }

    public static class Decryption
    {
        public const string ServerError = "[SERVER-DECRYPT-ERROR]";
        public const string StateDesync = "[SERVER-STATE-DESYNC]";
    }

    public static class Keys
    {
        public const string Mismatch = "[KEY-MISMATCH]";
        public const string CompareError = "[KEY-COMPARE-ERROR]";
    }

    public static class Identity
    {
        public const string Ensure = "[ENSURE-IDENTITY]";
    }

    public static class Persistence
    {
        public const string SnapshotSave = "[SNAPSHOT-SAVE]";
        public const string DeleteMessageFailed = "[PERSISTENCE-DELETE-MSG-FAILED]";
        public const string DeleteSnapshotFailed = "[PERSISTENCE-DELETE-SNAP-FAILED]";
    }

    public static class Opaque
    {
        public const string RegistrationInit = "[OPAQUE-REG-INIT]";
        public const string SignInInit = "[OPAQUE-SIGNIN-INIT]";
    }

    public static class VerificationFlow
    {
        public const string InitiateFlow = "[InitiateFlow]";
        public const string Prefix = "[verification.flow";
        public const string Otp = "[verification.flow.otp]";
        public const string Session = "[verification.flow.session]";
        public const string SessionTimeout = "[verification.flow.session-timeout]";
        public const string SessionExtended = "[verification.flow.session-extended]";
        public const string WriterReplace = "[verification.flow.writer-replace]";
    }

    public static class ServerKeys
    {
        public const string GetServerPublicKeys = "[GetServerPublicKeys]";
    }
}
