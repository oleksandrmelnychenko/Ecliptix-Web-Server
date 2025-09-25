using System.Reflection;
using System.Runtime.InteropServices;

namespace Ecliptix.Security.Certificate.Pinning.NativeResolver;

internal static unsafe class EcliptixServerNativeLibrary
{
    private const string LibraryName = "libcertificate.pinning.server";

    static EcliptixServerNativeLibrary()
    {
        NativeLibrary.SetDllImportResolver(typeof(EcliptixServerNativeLibrary).Assembly, ImportResolver);
    }

    private static IntPtr ImportResolver(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName == LibraryName)
        {
            string extension;
            string fileName;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                extension = ".dll";
                fileName = "libcertificate.pinning.server.dll"; 
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                extension = ".dylib";
                fileName = $"{LibraryName}{extension}";
            }
            else
            {
                extension = ".so";
                fileName = $"{LibraryName}{extension}";
            }

            string[] searchPaths =
            [
                Path.Combine(AppContext.BaseDirectory, fileName),
                Path.Combine(AppContext.BaseDirectory, "runtimes", GetRuntimeIdentifier(), "native", fileName),
                Path.Combine(Path.GetDirectoryName(assembly.Location) ?? "", fileName)
            ];

            foreach (string libPath in searchPaths)
            {
                if (File.Exists(libPath))
                {
                    try
                    {
                        return NativeLibrary.Load(libPath);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Failed to load library at {libPath}: {ex.Message}");
                    }
                }
            }
        }

        return IntPtr.Zero;
    }

    private static string GetRuntimeIdentifier()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return RuntimeInformation.ProcessArchitecture switch
            {
                Architecture.X64 => "win-x64",
                Architecture.X86 => "win-x86",
                Architecture.Arm64 => "win-arm64",
                _ => "win-x64"
            };
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return RuntimeInformation.ProcessArchitecture switch
            {
                Architecture.X64 => "linux-x64",
                Architecture.Arm64 => "linux-arm64",
                _ => "linux-x64"
            };
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return RuntimeInformation.ProcessArchitecture switch
            {
                Architecture.X64 => "osx-x64",
                Architecture.Arm64 => "osx-arm64",
                _ => "osx-arm64"
            };
        }

        return "unknown";
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