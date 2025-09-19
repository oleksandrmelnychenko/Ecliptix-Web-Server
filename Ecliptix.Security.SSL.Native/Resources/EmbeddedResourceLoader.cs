using System.Reflection;
using System.Text;

namespace Ecliptix.Security.SSL.Native.Resources;

internal static class EmbeddedResourceLoader
{
    public static string LoadEd25519PrivateKey()
    {
        return LoadEmbeddedResource("Resources.Ed25519PrivateKey");
    }

    public static string LoadRsaServerPrivateKey()
    {
        return LoadEmbeddedResource("Resources.RsaServerPrivateKey");
    }

    private static string LoadEmbeddedResource(string resourceName)
    {
        var assembly = Assembly.GetExecutingAssembly();

        using var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream == null)
        {
            throw new InvalidOperationException($"Embedded resource '{resourceName}' not found.");
        }

        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    public static byte[] GetEd25519PrivateKeyBytes()
    {
        return Encoding.UTF8.GetBytes(LoadEd25519PrivateKey());
    }

    public static byte[] GetRsaServerPrivateKeyBytes()
    {
        return Encoding.UTF8.GetBytes(LoadRsaServerPrivateKey());
    }
}