using System.Runtime.InteropServices;

namespace Ecliptix.Security.Certificate.Pinning.NativeResolver;

internal static unsafe class CertificatePinningNativeLibrary
{
    private const string LibraryName = "ecliptix.pinning";

    [DllImport(LibraryName, EntryPoint = "ecliptix_relay_init", CallingConvention = CallingConvention.Cdecl)]
    public static extern int Initialize();

    [DllImport(LibraryName, EntryPoint = "ecliptix_relay_init_with_keys", CallingConvention = CallingConvention.Cdecl)]
    public static extern int InitializeWithKeys(
        byte* rsaPrivateKeyDer, nuint rsaKeyLen,
        byte* ed25519PrivateKey, nuint ed25519KeyLen);

    [DllImport(LibraryName, EntryPoint = "ecliptix_relay_cleanup", CallingConvention = CallingConvention.Cdecl)]
    public static extern void Cleanup();

    [DllImport(LibraryName, EntryPoint = "ecliptix_relay_get_error", CallingConvention = CallingConvention.Cdecl)]
    public static extern byte* GetErrorMessage();

    [DllImport(LibraryName, EntryPoint = "ecliptix_relay_encrypt", CallingConvention = CallingConvention.Cdecl)]
    public static extern int Encrypt(
        byte* plaintext, nuint plainLen,
        byte* ciphertext, nuint* cipherLen);

    [DllImport(LibraryName, EntryPoint = "ecliptix_relay_decrypt", CallingConvention = CallingConvention.Cdecl)]
    public static extern int Decrypt(
        byte* ciphertext, nuint cipherLen,
        byte* plaintext, nuint* plainLen);

    [DllImport(LibraryName, EntryPoint = "ecliptix_relay_sign", CallingConvention = CallingConvention.Cdecl)]
    public static extern int Sign(
        byte* data, nuint dataLen,
        byte* signature, nuint* sigLen);

    [DllImport(LibraryName, EntryPoint = "ecliptix_generate_rsa_keypair", CallingConvention = CallingConvention.Cdecl)]
    public static extern int GenerateRsaKeypair(
        byte* privateKeyDer, nuint* privateKeyLen,
        byte* publicKeyDer, nuint* publicKeyLen);

    [DllImport(LibraryName, EntryPoint = "ecliptix_generate_ed25519_keypair", CallingConvention = CallingConvention.Cdecl)]
    public static extern int GenerateEd25519Keypair(
        byte* privateKey, nuint* privateKeyLen,
        byte* publicKey, nuint* publicKeyLen);

    [DllImport(LibraryName, EntryPoint = "ecliptix_secure_wipe", CallingConvention = CallingConvention.Cdecl)]
    public static extern void SecureWipe(void* data, nuint len);
}
