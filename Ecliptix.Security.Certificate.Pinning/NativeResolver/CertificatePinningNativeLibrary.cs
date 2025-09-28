using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Ecliptix.Security.Certificate.Pinning.NativeResolver;

internal static unsafe class CertificatePinningNativeLibrary
{
    private const string LibraryName = "libcertificate.pinning.server";

    static CertificatePinningNativeLibrary()
    {
        NativeLibrary.SetDllImportResolver(typeof(CertificatePinningNativeLibrary).Assembly, ImportResolver);
    }

    private static IntPtr ImportResolver(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != LibraryName) return IntPtr.Zero;

        (string fileName, string[] fallbackNames) = GetLibraryFileNames();
        string[] allNames = [fileName, .. fallbackNames];

        string[] searchPaths = GetSearchPaths(assembly, allNames);
        List<string> attemptedPaths = [];
        List<string> loadErrors = [];

        foreach (string libPath in searchPaths)
        {
            attemptedPaths.Add(libPath);

            if (!File.Exists(libPath))
            {
                loadErrors.Add($"{libPath}: File not found");
                continue;
            }

            try
            {
                return NativeLibrary.Load(libPath);
            }
            catch (Exception ex)
            {
                loadErrors.Add($"{libPath}: {ex.Message}");
            }
        }

        string runtimeId = GetRuntimeIdentifier();
        string errorMessage = $"Failed to load native library '{LibraryName}' for {runtimeId}.\n" +
                              $"Attempted paths:\n{string.Join("\n", attemptedPaths)}\n" +
                              $"Errors:\n{string.Join("\n", loadErrors)}";

        Trace.WriteLine(errorMessage, "CertificatePinningNativeLibrary");

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            try
            {
                using EventLog eventLog = new("Application");
                eventLog.Source = "Ecliptix.CertificatePinning";
                eventLog.WriteEntry(errorMessage, EventLogEntryType.Warning);
            }
            catch
            {
                // Ignore 
            }
        }

        return IntPtr.Zero;
    }

    private static (string primary, string[] fallbacks) GetLibraryFileNames()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return ("libcertificate.pinning.server.dll", ["certificate.pinning.server.dll"]);
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return ($"{LibraryName}.dylib", ["certificate.pinning.server.dylib"]);
        }
        else
        {
            return ($"{LibraryName}.so", ["certificate.pinning.server.so"]);
        }
    }

    private static string[] GetSearchPaths(Assembly assembly, string[] fileNames)
    {
        List<string> paths = [];
        string runtimeId = GetRuntimeIdentifier();

        foreach (string fileName in fileNames)
        {
            paths.Add(Path.Combine(AppContext.BaseDirectory, fileName));
            paths.Add(Path.Combine(AppContext.BaseDirectory, "runtimes", runtimeId, "native", fileName));
            paths.Add(Path.Combine(Path.GetDirectoryName(assembly.Location) ?? "", fileName));
        }

        return paths.ToArray();
    }

    private static string GetRuntimeIdentifier()
    {
        Architecture architecture = RuntimeInformation.ProcessArchitecture;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return architecture switch
            {
                Architecture.X64 => "win-x64",
                Architecture.X86 => "win-x86",
                Architecture.Arm64 => "win-arm64",
                Architecture.Arm => "win-arm",
                _ => throw new PlatformNotSupportedException($"Unsupported Windows architecture: {architecture}")
            };
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            bool isMusl = IsMuslLinux();
            string libcSuffix = isMusl ? "-musl" : "";

            return architecture switch
            {
                Architecture.X64 => $"linux{libcSuffix}-x64",
                Architecture.Arm64 => $"linux{libcSuffix}-arm64",
                Architecture.Arm => $"linux{libcSuffix}-arm",
                _ => throw new PlatformNotSupportedException($"Unsupported Linux architecture: {architecture}")
            };
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return architecture switch
            {
                Architecture.X64 => "osx-x64",
                Architecture.Arm64 => "osx-arm64",
                _ => throw new PlatformNotSupportedException($"Unsupported macOS architecture: {architecture}")
            };
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.FreeBSD))
        {
            return architecture switch
            {
                Architecture.X64 => "freebsd-x64",
                Architecture.Arm64 => "freebsd-arm64",
                _ => throw new PlatformNotSupportedException($"Unsupported FreeBSD architecture: {architecture}")
            };
        }

        throw new PlatformNotSupportedException($"Unsupported operating system: {RuntimeInformation.OSDescription}");
    }

    private static bool IsMuslLinux()
    {
        try
        {
            return File.Exists("/lib/ld-musl-x86_64.so.1") ||
                   File.Exists("/lib/ld-musl-aarch64.so.1") ||
                   Directory.Exists("/usr/lib/musl") ||
                   RuntimeInformation.OSDescription.Contains("Alpine", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
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
    public static extern CertificatePinningResult GenerateEd25519Keypair(
        byte* publicKey,
        byte* privateKey);

    [DllImport(LibraryName, EntryPoint = "ecliptix_server_sign_ed25519", CallingConvention = CallingConvention.Cdecl)]
    public static extern CertificatePinningResult SignEd25519(
        byte* message, nuint messageLen,
        byte* privateKey,
        byte* signature);

    [DllImport(LibraryName, EntryPoint = "ecliptix_server_verify_ed25519", CallingConvention = CallingConvention.Cdecl)]
    public static extern CertificatePinningResult VerifyEd25519(
        byte* message, nuint messageLen,
        byte* signature,
        byte* publicKey);
}