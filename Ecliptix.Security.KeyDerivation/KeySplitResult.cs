using System;
using System.Security.Cryptography;

namespace Ecliptix.Security.KeyDerivation;

public sealed class KeySplitResult : IDisposable
{
    public KeyShare[] Shares { get; private set; }
    public int Threshold { get; }
    public Guid SessionId { get; }
    public DateTime CreatedAt { get; }

    private bool _disposed;

    public KeySplitResult(KeyShare[]? shares, int threshold)
    {
        Shares = shares ?? Array.Empty<KeyShare>();
        Threshold = threshold;
        SessionId = Guid.NewGuid();
        CreatedAt = DateTime.UtcNow;
    }

    public void SetShares(KeyShare[] shares)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(KeySplitResult));

        Shares = shares ?? throw new ArgumentNullException(nameof(shares));
    }

    public void Dispose()
    {
        if (_disposed) return;

        foreach (KeyShare share in Shares)
        {
            share?.Dispose();
        }

        _disposed = true;
    }
}

public sealed class KeyShare : IDisposable
{
    public byte[] ShareData { get; private set; }
    public int ShareIndex { get; }
    public ShareLocation Location { get; }
    public byte[] ShareId { get; }
    public Guid SessionId { get; }
    public DateTime CreatedAt { get; }
    public byte[]? Hmac { get; private set; }

    private bool _disposed;

    public KeyShare(byte[] shareData, int index, ShareLocation location, Guid? sessionId = null)
    {
        ShareData = shareData ?? throw new ArgumentNullException(nameof(shareData));
        ShareIndex = index;
        Location = location;
        ShareId = RandomNumberGenerator.GetBytes(16);
        SessionId = sessionId ?? Guid.NewGuid();
        CreatedAt = DateTime.UtcNow;
    }

    public void SetHmac(byte[] hmac)
    {
        Hmac = hmac ?? throw new ArgumentNullException(nameof(hmac));
    }

    public void Dispose()
    {
        if (_disposed) return;

        if (ShareData != null && ShareData.Length > 0)
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