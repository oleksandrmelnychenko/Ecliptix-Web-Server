using System.Runtime.InteropServices;

namespace Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;

public static class PlatformDetector
{
    private static readonly Lazy<string> CachedPlatformInfo = new(() => DetectPlatform());
    private static readonly Lazy<string> CachedLocalIpAddress = new(() => DetectLocalIpAddress());

    public static string GetPlatformInfo() => CachedPlatformInfo.Value;

    public static string GetLocalIpAddress() => CachedLocalIpAddress.Value;

    private static string DetectPlatform()
    {
        string os = GetOperatingSystem();
        string arch = GetArchitecture();
        string runtime = GetRuntimeVersion();
        return $"{os}-{arch} (.NET {runtime})";
    }

    private static string GetOperatingSystem()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            return "macOS";
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return "Windows";
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            return "Linux";
        return "Unknown";
    }

    private static string GetArchitecture()
    {
        Architecture processArch = RuntimeInformation.ProcessArchitecture;
        return processArch switch
        {
            Architecture.Arm64 => "ARM64",
            Architecture.X64 => "x64",
            Architecture.X86 => "x86",
            Architecture.Arm => "ARM32",
            _ => processArch.ToString()
        };
    }

    private static string GetRuntimeVersion()
    {
        string frameworkDescription = RuntimeInformation.FrameworkDescription;
        int startIndex = frameworkDescription.IndexOf(' ');
        if (startIndex >= 0 && startIndex < frameworkDescription.Length - 1)
        {
            return frameworkDescription[(startIndex + 1)..];
        }
        return frameworkDescription;
    }

    private static string DetectLocalIpAddress()
    {
        try
        {
            System.Net.NetworkInformation.NetworkInterface[] interfaces =
                System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces();

            foreach (System.Net.NetworkInformation.NetworkInterface iface in interfaces)
            {
                if (iface.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up)
                    continue;

                if (iface.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
                    continue;

                System.Net.NetworkInformation.IPInterfaceProperties properties = iface.GetIPProperties();
                foreach (System.Net.NetworkInformation.UnicastIPAddressInformation unicast in properties.UnicastAddresses)
                {
                    if (unicast.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        return unicast.Address.ToString();
                    }
                }
            }

            return "127.0.0.1";
        }
        catch
        {
            return "127.0.0.1";
        }
    }
}
