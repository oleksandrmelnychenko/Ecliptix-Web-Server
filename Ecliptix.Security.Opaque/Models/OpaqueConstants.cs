namespace Ecliptix.Security.Opaque.Models;

public static class OpaqueConstants
{
    public const int OPRF_SEED_LENGTH = 32;
    public const int PRIVATE_KEY_LENGTH = 32;
    public const int PUBLIC_KEY_LENGTH = 32;
    public const int NONCE_LENGTH = 32;
    public const int MAC_LENGTH = 64;
    public const int HASH_LENGTH = 64;
    public const int ENVELOPE_LENGTH = 176; // 32 (nonce) + 128 (ciphertext: 32+32+32+32 for server_pubkey, client_privkey, client_pubkey, master_key) + 16 (auth_tag)
    public const int REGISTRATION_REQUEST_LENGTH = 32;
    public const int REGISTRATION_RESPONSE_LENGTH = 96;
    public const int CREDENTIAL_REQUEST_LENGTH = 96;
    public const int CREDENTIAL_RESPONSE_LENGTH = 208; // 32 (OPRF response) + 176 (envelope)
    public const int KE1_LENGTH = 96;
    public const int KE2_LENGTH = 336; // 32 (nonce) + 32 (pubkey) + 208 (credential_response) + 64 (MAC)
    public const int KE3_LENGTH = 64;
    public const int SERVER_CREDENTIALS_LENGTH = 240; // 176 (envelope) + 32 (masking_key) + 32 (export_key)
    public const int MASKING_KEY_LENGTH = 32;
}
