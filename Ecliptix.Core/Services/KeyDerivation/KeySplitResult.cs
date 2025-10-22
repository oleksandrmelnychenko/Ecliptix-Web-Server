using System.Security.Cryptography;

namespace Ecliptix.Core.Services.KeyDerivation;

public sealed class KeySplitResult(KeyShare[]? shares) : IDisposable
{
    public KeyShare[] Shares { get; private set; } = shares ?? [];
    public Guid SessionId { get; } = Guid.NewGuid();

    private bool _disposed;

    public void SetShares(KeyShare[] shares)
    {
        if (!_disposed)
        {
            Shares = shares;
        }
        else
        {
            throw new ObjectDisposedException(nameof(KeySplitResult));
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        foreach (KeyShare share in Shares)
        {
            share.Dispose();
        }

        _disposed = true;
    }
}

public sealed class KeyShare(byte[] shareData, int index, ShareLocation location, Guid? sessionId = null)
    : IDisposable
{
    public byte[] ShareData { get; private set; } = shareData;
    public int ShareIndex { get; } = index;
    public ShareLocation Location { get; } = location;
    public byte[] ShareId { get; } = RandomNumberGenerator.GetBytes(16);
    public Guid SessionId { get; } = sessionId ?? Guid.NewGuid();
    public DateTime CreatedAt { get; } = DateTime.UtcNow;
    public byte[]? Hmac { get; private set; }

    private bool _disposed;

    public void SetHmac(byte[] hmac)
    {
        Hmac = hmac;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        if (ShareData.Length > 0)
        {
            CryptographicOperations.ZeroMemory(ShareData);
            ShareData = null!;
        }

        _disposed = true;
    }
}

public enum ShareLocation
{
    HardwareSecurity,
    PlatformKeychain,
    SecureMemory,
    LocalEncrypted,
    BackupStorage
}
