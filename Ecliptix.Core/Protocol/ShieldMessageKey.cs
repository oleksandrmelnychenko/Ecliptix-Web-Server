using Ecliptix.Core.Protocol.Utilities;

namespace Ecliptix.Core.Protocol;

public readonly struct ShieldMessageKey : IEquatable<ShieldMessageKey>
{
    public readonly uint Index;
    private readonly byte[] _key; 

    public ShieldMessageKey(uint index, ReadOnlySpan<byte> key)
    {
        if (key.Length != Constants.X25519KeySize) 
            throw new ArgumentException($"Key must be {Constants.X25519KeySize} bytes long.", nameof(key));
        Index = index;
        _key = key.ToArray();
    }

    public ReadOnlySpan<byte> Key => _key;

    public ShieldMessageKey Clone() => new(Index, _key);

    public bool Equals(ShieldMessageKey other)
    {
        return Index == other.Index && Key.SequenceEqual(other.Key);
    }

    public override bool Equals(object? obj) => obj is ShieldMessageKey other && Equals(other);

    public override int GetHashCode()
    {
        HashCode hash = default;
        hash.Add(Index);
        foreach (byte b in _key)
        {
            hash.Add(b);
        }
        return hash.ToHashCode();
    }

    public static bool operator ==(ShieldMessageKey left, ShieldMessageKey right) => left.Equals(right);
    public static bool operator !=(ShieldMessageKey left, ShieldMessageKey right) => !left.Equals(right);
}