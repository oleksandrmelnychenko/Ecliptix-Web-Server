namespace Ecliptix.Security.Opaque.Models;

public static class OpaqueConstants
{
    public const int OPRF_SEED_LENGTH = 32;
    public const int PRIVATE_KEY_LENGTH = 32;
    public const int PUBLIC_KEY_LENGTH = 32;
    public const int NONCE_LENGTH = 32;
    public const int MAC_LENGTH = 64;
    public const int HASH_LENGTH = 64;
    public const int ENVELOPE_LENGTH = 144;
    public const int REGISTRATION_REQUEST_LENGTH = 32;
    public const int REGISTRATION_RESPONSE_LENGTH = 96;
    public const int CREDENTIAL_REQUEST_LENGTH = 96;
    public const int CREDENTIAL_RESPONSE_LENGTH = 176;
    public const int KE1_LENGTH = 96;
    public const int KE2_LENGTH = 304;
    public const int KE3_LENGTH = 64;
    public const int SERVER_CREDENTIALS_LENGTH = 208; // ENVELOPE_LENGTH + PRIVATE_KEY_LENGTH + PUBLIC_KEY_LENGTH
    public const int MASKING_KEY_LENGTH = 32;
}