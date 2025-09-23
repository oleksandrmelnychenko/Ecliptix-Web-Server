using System.Runtime.InteropServices;
using System.Reflection;

namespace Ecliptix.Security.SSL.Native.Native;

internal static unsafe class EcliptixServerNativeLibrary
{
    private const string LibraryName = "libecliptix.server";

    static EcliptixServerNativeLibrary()
    {
        NativeLibrary.SetDllImportResolver(typeof(EcliptixServerNativeLibrary).Assembly, ImportResolver);
    }

    private static IntPtr ImportResolver(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName == LibraryName)
        {
            string extension = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? ".dll" :
                              RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? ".dylib" : ".so";

            string libPath = Path.Combine(AppContext.BaseDirectory, $"{LibraryName}{extension}");

            if (File.Exists(libPath))
            {
                return NativeLibrary.Load(libPath);
            }
        }

        return IntPtr.Zero;
    }

    [DllImport(LibraryName, EntryPoint = "ecliptix_server_init", CallingConvention = CallingConvention.Cdecl)]
    public static extern int Initialize();

    [DllImport(LibraryName, EntryPoint = "ecliptix_server_init_with_key", CallingConvention = CallingConvention.Cdecl)]
    public static extern int InitializeWithKey(byte* privateKeyPem, nuint keySize);

    [DllImport(LibraryName, EntryPoint = "ecliptix_server_init_with_keys", CallingConvention = CallingConvention.Cdecl)]
    public static extern int InitializeWithKeys(
        byte* serverPrivatePem, nuint serverKeySize,
        byte* clientPublicPem, nuint clientPubSize);

    [DllImport(LibraryName, EntryPoint = "ecliptix_server_cleanup", CallingConvention = CallingConvention.Cdecl)]
    public static extern void Cleanup();

    [DllImport(LibraryName, EntryPoint = "ecliptix_server_get_error", CallingConvention = CallingConvention.Cdecl)]
    public static extern byte* GetErrorMessage();

    [DllImport(LibraryName, EntryPoint = "ecliptix_server_encrypt", CallingConvention = CallingConvention.Cdecl)]
    public static extern int Encrypt(
        byte* plaintext, nuint plainLen,
        byte* ciphertext, nuint* cipherLen);

    [DllImport(LibraryName, EntryPoint = "ecliptix_server_decrypt", CallingConvention = CallingConvention.Cdecl)]
    public static extern int Decrypt(
        byte* ciphertext, nuint cipherLen,
        byte* plaintext, nuint* plainLen);

    [DllImport(LibraryName, EntryPoint = "ecliptix_server_sign", CallingConvention = CallingConvention.Cdecl)]
    public static extern int Sign(
        byte* data, nuint dataLen,
        byte* signature, nuint* sigLen);

    [DllImport(LibraryName, EntryPoint = "ecliptix_server_generate_ed25519_keypair", CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixServerResult GenerateEd25519Keypair(
        byte* publicKey,
        byte* privateKey);

    [DllImport(LibraryName, EntryPoint = "ecliptix_server_sign_ed25519", CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixServerResult SignEd25519(
        byte* message, nuint messageLen,
        byte* privateKey,
        byte* signature);

    [DllImport(LibraryName, EntryPoint = "ecliptix_server_verify_ed25519", CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixServerResult VerifyEd25519(
        byte* message, nuint messageLen,
        byte* signature,
        byte* publicKey);
}