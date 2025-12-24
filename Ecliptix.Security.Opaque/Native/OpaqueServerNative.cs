using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Ecliptix.Security.Opaque.Native;

internal static class OpaqueServerNative
{
    private const string ServerLibrary = "libopaque_server";

    static OpaqueServerNative()
    {
        NativeLibrary.SetDllImportResolver(typeof(OpaqueServerNative).Assembly, ImportResolver);
    }

    private static IntPtr ImportResolver(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (!string.Equals(libraryName, ServerLibrary, StringComparison.Ordinal))
        {
            return IntPtr.Zero;
        }

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
        string errorMessage = $"Failed to load native library '{ServerLibrary}' for {runtimeId}.\n" +
                              $"Attempted paths:\n{string.Join("\n", attemptedPaths)}\n" +
                              $"Errors:\n{string.Join("\n", loadErrors)}";

        Trace.WriteLine(errorMessage, "OpaqueServerNative");

        return IntPtr.Zero;
    }

    private static (string primary, string[] fallbacks) GetLibraryFileNames()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return ("libopaque_server.dll", ["opaque_server.dll"]);
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return ("libopaque_server.dylib", ["opaque_server.dylib"]);
        }

        return ("libopaque_server.so", ["opaque_server.so"]);
    }

    private static string[] GetSearchPaths(Assembly assembly, string[] fileNames)
    {
        List<string> paths = [];
        string runtimeId = GetRuntimeIdentifier();

        foreach (string fileName in fileNames)
        {
            paths.Add(Path.Combine(AppContext.BaseDirectory, fileName));
            paths.Add(Path.Combine(AppContext.BaseDirectory, "runtimes", runtimeId, "native", fileName));
            paths.Add(Path.Combine(Path.GetDirectoryName(assembly.Location) ?? string.Empty, fileName));
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
            string libcSuffix = isMusl ? "-musl" : string.Empty;

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

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_keypair_generate(out nint handle);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_create_default(out nint handle);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_create_with_keys(
        [In] byte[] privateKey, nuint privateKeyLen,
        [In] byte[] publicKey, nuint publicKeyLen,
        out nint serverHandle);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_derive_keypair_from_seed(
        [In] byte[] seed, nuint seedLen,
        [Out] byte[] privateKey, nuint privateKeyBufferLen,
        [Out] byte[] publicKey, nuint publicKeyBufferLen);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern void opaque_server_keypair_destroy(nint handle);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_keypair_get_public_key(
        nint handle,
        [Out] byte[] public_key,
        nuint key_buffer_size);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_create(
        nint keypair_handle,
        out nint handle);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern void opaque_server_destroy(nint handle);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_state_create(out nint handle);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern void opaque_server_state_destroy(nint handle);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_create_registration_response(
        nint server_handle,
        [In] byte[] request_data,
        nuint request_length,
        [Out] byte[] response_data,
        nuint response_buffer_size,
        [Out] byte[] credentials_data,
        nuint credentials_buffer_size);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_generate_ke2(
        nint server_handle,
        [In] byte[] ke1_data,
        nuint ke1_length,
        [In] byte[] credentials_data,
        nuint credentials_length,
        [Out] byte[] ke2_data,
        nuint ke2_buffer_size,
        nint state_handle);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_finish(
        nint server_handle,
        [In] byte[] ke3_data,
        nuint ke3_length,
        nint state_handle,
        [Out] byte[] session_key,
        nuint session_key_buffer_size);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern nint opaque_server_get_version();

}
