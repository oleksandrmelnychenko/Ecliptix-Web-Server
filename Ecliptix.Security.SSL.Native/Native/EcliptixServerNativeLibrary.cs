/*
 * Ecliptix Security SSL Native Library
 * P/Invoke wrapper for the Ecliptix server security library
 * Author: Oleksandr Melnychenko
 */

using System.Runtime.InteropServices;
using System.Reflection;

namespace Ecliptix.Security.SSL.Native.Native;

internal static unsafe class EcliptixServerNativeLibrary
{
    private const string LibraryName = "libecliptix_server_security";

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

    #region Library Management

    [DllImport(LibraryName, EntryPoint = "ecliptix_server_init", CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixServerResult Initialize();

    [DllImport(LibraryName, EntryPoint = "ecliptix_server_cleanup", CallingConvention = CallingConvention.Cdecl)]
    public static extern void Cleanup();

    [DllImport(LibraryName, EntryPoint = "ecliptix_server_get_error_message", CallingConvention = CallingConvention.Cdecl)]
    public static extern byte* GetErrorMessage();

    #endregion

    #region RSA Encryption/Decryption

    [DllImport(LibraryName, EntryPoint = "ecliptix_server_encrypt_rsa", CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixServerResult EncryptRSA(
        byte* plaintext, nuint plaintextSize,
        byte* publicKeyPem, nuint publicKeySize,
        byte* ciphertext, nuint* ciphertextSize);

    [DllImport(LibraryName, EntryPoint = "ecliptix_server_decrypt_rsa", CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixServerResult DecryptRSA(
        byte* ciphertext, nuint ciphertextSize,
        byte* plaintext, nuint* plaintextSize);

    #endregion

    #region Digital Signature Creation

    [DllImport(LibraryName, EntryPoint = "ecliptix_server_sign_ed25519", CallingConvention = CallingConvention.Cdecl)]
    public static extern EcliptixServerResult SignEd25519(
        byte* message, nuint messageSize, byte* signature);

    #endregion
}