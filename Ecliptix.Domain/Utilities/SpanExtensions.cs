using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Ecliptix.Domain.Utilities;

public static class SpanExtensions
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ConcatenateTo(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, Span<byte> destination)
    {
        if (destination.Length < first.Length + second.Length)
            throw new ArgumentException("Destination span is too small");
            
        first.CopyTo(destination);
        second.CopyTo(destination[first.Length..]);
    }
    
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ConcatenateTo(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, ReadOnlySpan<byte> third, Span<byte> destination)
    {
        if (destination.Length < first.Length + second.Length + third.Length)
            throw new ArgumentException("Destination span is too small");
            
        first.CopyTo(destination);
        second.CopyTo(destination[first.Length..]);
        third.CopyTo(destination[(first.Length + second.Length)..]);
    }
    
    public static byte[] RentAndConcatenate(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
    {
        int totalLength = first.Length + second.Length;
        byte[] result = new byte[totalLength];
        ConcatenateTo(first, second, result);
        return result;
    }
    
    public static void SecureClear(Span<byte> span)
    {
        CryptographicOperations.ZeroMemory(span);
    }
    
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool ConstantTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        return CryptographicOperations.FixedTimeEquals(left, right);
    }
    
    public static void WriteInt32BigEndian(Span<byte> destination, int value)
    {
        if (destination.Length < sizeof(int))
            throw new ArgumentException("Destination span is too small");
            
        if (BitConverter.IsLittleEndian)
        {
            Span<byte> temp = stackalloc byte[sizeof(int)];
            MemoryMarshal.Write(temp, value);
            temp.Reverse();
            temp.CopyTo(destination);
        }
        else
        {
            MemoryMarshal.Write(destination, value);
        }
    }
    
    public static int ReadInt32BigEndian(ReadOnlySpan<byte> source)
    {
        if (source.Length < sizeof(int))
            throw new ArgumentException("Source span is too small");
            
        if (BitConverter.IsLittleEndian)
        {
            Span<byte> temp = stackalloc byte[sizeof(int)];
            source[..sizeof(int)].CopyTo(temp);
            temp.Reverse();
            return MemoryMarshal.Read<int>(temp);
        }
        else
        {
            return MemoryMarshal.Read<int>(source);
        }
    }
    
    public static bool TryWriteToStackAlloc<T>(ReadOnlySpan<T> source, Span<T> destination, out int written) where T : struct
    {
        written = 0;
        if (destination.Length < source.Length)
            return false;
            
        source.CopyTo(destination);
        written = source.Length;
        return true;
    }
}