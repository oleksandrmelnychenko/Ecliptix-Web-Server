namespace Ecliptix.Domain.Memberships.OPAQUE;

public static class OpaqueConstants
{
    public static ReadOnlySpan<byte> OprfKeyInfo => "Ecliptix-OPAQUE-OPRFKey"u8;
    public static ReadOnlySpan<byte> TokenKeyInfo => "Ecliptix-OPAQUE-TokenKey"u8;
    public static ReadOnlySpan<byte> ServerStaticKeyInfo => "Ecliptix-OPAQUE-ServerStaticKey"u8;
    public static ReadOnlySpan<byte> CredentialKeyInfo => "Ecliptix-OPAQUE-CredentialKey"u8;
    public static ReadOnlySpan<byte> AkeSalt => "OPAQUE-AKE-Salt"u8;
    public static ReadOnlySpan<byte> SessionKeyInfo => "session_key"u8;
    public static ReadOnlySpan<byte> ClientMacKeyInfo => "client_mac_key"u8;
    public static ReadOnlySpan<byte> ServerMacKeyInfo => "server_mac_key"u8;

    public static ReadOnlySpan<byte> ProtocolVersion => "Ecliptix-OPAQUE-v1"u8;

    public const int CompressedPublicKeyLength = 33;
    public const int DefaultKeyLength = 32;
    public const int MacKeyLength = 32;
    public const int ScalarSize = 32;
    public const int HashLength = 32;
    public const int NonceLength = 32;

    public const int AesGcmNonceLengthBytes = 12;
    public const int AesGcmTagLengthBits = 128;

    public const int Pbkdf2Iterations = 100000;
    public const int Pbkdf2SaltLength = 32;
    public const int Argon2idMemoryCost = 65536;
    public const int Argon2idTimeCost = 3;
    public const int Argon2idParallelism = 1;

    public static ReadOnlySpan<byte> ExportKeyInfo => "ExportKey"u8;
    public static ReadOnlySpan<byte> AuthKeyInfo => "AuthKey"u8;
    public static ReadOnlySpan<byte> PrivateKeyInfo => "PrivateKey"u8;
    public static ReadOnlySpan<byte> CredentialResponsePadInfo => "CredentialResponsePad"u8;
    public static ReadOnlySpan<byte> HandshakeSecretInfo => "HandshakeSecret"u8;
    public static ReadOnlySpan<byte> PasswordChangeKeyInfo => "PasswordChangeKey"u8;
    public static ReadOnlySpan<byte> RecoveryTokenKeyInfo => "RecoveryTokenKey"u8;
    public static ReadOnlySpan<byte> SessionTokenKeyInfo => "SessionTokenKey"u8;

    public const string DefaultServerIdentity = "server.ecliptix.com";
    public const string OpaqueVersion = "OPAQUE-3DH";
    public const int ProtocolOverheadBytes = 96;

    public const int SessionTokenLength = 32;
    public const int RecoveryTokenLength = 16;
    public const int RecoveryCodeLength = 6;
    public const int DefaultSessionExpirationMinutes = 60;
    public const int DefaultRecoveryExpirationMinutes = 15;

    public const int MaxInputLength = 16384;
    public const int MaxPhoneNumberLength = 32;
    public const int MaxRegistrationRecordLength = 256;
    public const int MinRegistrationRecordLength = CompressedPublicKeyLength + NonceLength + HashLength;

    public static class RfcCompliance
    {
        public const bool EnableOprfMasking = false;
        public const bool EnableRegistrationRecordMasking = true;
        public const bool EnableStretching = true;
        public const bool EnforcePointValidation = true;
        public const bool UseMacEnvelopes = true;
        public const bool IncludeServerIdentityInTranscript = true;
    }

    public static class ErrorMessages
    {
        public const string InvalidRegistrationRecordTooShort = "Invalid registration record: too short.";
        public const string EnvelopeMacVerificationFailed = "Envelope MAC verification failed";
        public const string ServerMacVerificationFailed = "Server MAC verification failed.";
        public const string InvalidOprfResponsePoint = "Invalid OPRF response point: ";
        public const string InvalidServerStaticPublicKey = "Invalid server static public key: ";
        public const string InvalidServerEphemeralPublicKey = "Invalid server ephemeral public key: ";
        public const string PointAtInfinity = "Point is at infinity";
        public const string PointNotValid = "Point is not valid";
        public const string SubgroupCheckFailed = "Point not in main subgroup";
        public const string OprfOutputEmpty = "OPRF output cannot be empty";
        public const string EnvelopeTooShort = "Envelope too short";
        public const string MacEnvelopeCreationFailed = "MAC envelope creation failed: ";
        public const string MacVerificationFailed = "MAC verification failed: ";
        public const string ExportKeyDerivationFailed = "Export key derivation failed: ";
        public const string Pbkdf2Failed = "PBKDF2 failed: ";
        public const string PasswordChangeFailed = "Password change failed: ";
        public const string InvalidCurrentPassword = "Current password is invalid";
        public const string SessionTokenInvalid = "Session token is invalid";
        public const string SessionTokenExpired = "Session token has expired";
        public const string RecoveryTokenInvalid = "Recovery token is invalid";
        public const string RecoveryTokenExpired = "Recovery token has expired";
        public const string RecoveryCodeInvalid = "Recovery verification code is invalid";
        public const string AccountNotFound = "Account not found";
        public const string RateLimitExceeded = "Rate limit exceeded";
    }

    public static class ProtocolIndices
    {
        public const int DhTripleCount = 3;
        public const int BigIntegerPositiveSign = 1;
        public const int DhFirstOffset = 0;
        public const int DhSecondOffset = 1;
        public const int DhThirdOffset = 2;
    }

    public static class CryptographicFlags
    {
        public const bool CompressedPointEncoding = true;
        public const bool ClearOnDispose = false;
    }

    public static class CryptographicConstants
    {
        public const string EllipticCurveName = "secp256r1";
        public const byte PointCompressionPrefix = 0x02;
        public const int MaxHashToPointAttempts = 255;
        public const int BigIntegerPositiveSign = 1;
    }

    public static class HkdfInfoStrings
    {
        public static ReadOnlySpan<byte> OpaqueSalt => "OPAQUE-Salt"u8;
    }
}