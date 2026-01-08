using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Failures;
using Ecliptix.SharedKernel.Failures.Sodium;

namespace Ecliptix.Core.Services.KeyDerivation;

public sealed class NativeSecretSharingService : ISecretSharingService
{
    private const int DefaultThreshold = 3;
    private const int DefaultTotalShares = 5;
    private const int MinimumShares = 2;
    private const int MaximumShares = 255;
    private const int MaxKeyLength = 1024 * 1024;
    private const int ShareHeaderSize = 12;
    private const int AuthTagSize = 32;
    private const int AuthKeyLength = 32;

    private static readonly byte[] ShareMagic = [(byte)'E', (byte)'S', (byte)'S', (byte)'1'];

    public async Task<Result<KeySplitResult, KeySplittingFailure>> SplitKeyAsync(
        SodiumSecureMemoryHandle keyHandle,
        int threshold = DefaultThreshold,
        int totalShares = DefaultTotalShares,
        SodiumSecureMemoryHandle? hmacKeyHandle = null)
    {
        if (keyHandle.IsInvalid)
        {
            return Result<KeySplitResult, KeySplittingFailure>.Err(
                KeySplittingFailure.InvalidKeyData("Key handle cannot be null or invalid"));
        }

        if (threshold < MinimumShares || threshold > totalShares)
        {
            return Result<KeySplitResult, KeySplittingFailure>.Err(
                KeySplittingFailure.InvalidThreshold(threshold, totalShares));
        }

        if (totalShares is < MinimumShares or > MaximumShares)
        {
            return Result<KeySplitResult, KeySplittingFailure>.Err(
                KeySplittingFailure.InvalidShareCount(totalShares));
        }

        if (keyHandle.Length is <= 0 or > MaxKeyLength)
        {
            return Result<KeySplitResult, KeySplittingFailure>.Err(
                KeySplittingFailure.InvalidKeyLength(keyHandle.Length));
        }

        byte[]? keyBytes = null;
        byte[]? authKeyBytes = null;

        try
        {
            Result<byte[], SodiumFailure> readResult = keyHandle.ReadBytes(keyHandle.Length);
            if (readResult.IsErr)
            {
                return Result<KeySplitResult, KeySplittingFailure>.Err(
                    KeySplittingFailure.MemoryReadFailed(readResult.UnwrapErr().Message));
            }

            keyBytes = readResult.Unwrap();

            if (hmacKeyHandle is { IsInvalid: false })
            {
                Result<byte[], SodiumFailure> hmacReadResult = hmacKeyHandle.ReadBytes(hmacKeyHandle.Length);
                if (hmacReadResult.IsErr)
                {
                    return Result<KeySplitResult, KeySplittingFailure>.Err(
                        KeySplittingFailure.HmacKeyRetrievalFailed(hmacReadResult.UnwrapErr().Message));
                }

                authKeyBytes = hmacReadResult.Unwrap();
                if (authKeyBytes.Length == 0)
                {
                    authKeyBytes = null;
                }
                else if (authKeyBytes.Length != AuthKeyLength)
                {
                    return Result<KeySplitResult, KeySplittingFailure>.Err(
                        KeySplittingFailure.InvalidKeyData("Auth key must be 32 bytes"));
                }
            }

            return await Task.Run(() =>
            {
                IntPtr bufferPtr = IntPtr.Zero;
                try
                {
                    bufferPtr = NativeSecretSharingInterop.ecliptix_buffer_allocate(0);
                    if (bufferPtr == IntPtr.Zero)
                    {
                        return Result<KeySplitResult, KeySplittingFailure>.Err(
                            KeySplittingFailure.AllocationFailed("Failed to allocate share buffer"));
                    }

                    NativeSecretSharingInterop.EcliptixErrorCode result =
                        NativeSecretSharingInterop.ecliptix_secret_sharing_split(
                            keyBytes,
                            (nuint)keyBytes.Length,
                            (byte)threshold,
                            (byte)totalShares,
                            authKeyBytes,
                            (nuint)(authKeyBytes?.Length ?? 0),
                            bufferPtr,
                            out nuint shareLength,
                            out NativeSecretSharingInterop.EcliptixError error);

                    if (result != NativeSecretSharingInterop.EcliptixErrorCode.Success)
                    {
                        string message = error.GetMessage();
                        NativeSecretSharingInterop.ecliptix_error_free(ref error);
                        return Result<KeySplitResult, KeySplittingFailure>.Err(
                            MapSplitError(result, message));
                    }

                    NativeSecretSharingInterop.EcliptixBuffer buffer =
                        Marshal.PtrToStructure<NativeSecretSharingInterop.EcliptixBuffer>(bufferPtr);

                    if (buffer.Length == 0 || shareLength == 0)
                    {
                        return Result<KeySplitResult, KeySplittingFailure>.Err(
                            KeySplittingFailure.KeySplittingFailed("Native split returned empty shares"));
                    }

                    if (buffer.Length % shareLength != 0)
                    {
                        return Result<KeySplitResult, KeySplittingFailure>.Err(
                            KeySplittingFailure.InvalidShareData("Share buffer length mismatch"));
                    }

                    int shareSize = checked((int)shareLength);
                    int shareCount = checked((int)(buffer.Length / shareLength));

                    int bufferLength = checked((int)buffer.Length);
                    byte[] shareBytes = new byte[bufferLength];
                    Marshal.Copy(buffer.Data, shareBytes, 0, bufferLength);

                    KeyShare[] shares = new KeyShare[shareCount];
                    KeySplitResult splitResult = new(null!);
                    Guid sessionId = splitResult.SessionId;
                    int locationCount = Enum.GetValues<ShareLocation>().Length;

                    HashSet<int> seenIndices = [];

                    for (int i = 0; i < shareCount; i++)
                    {
                        byte[] shareData = new byte[shareSize];
                        Buffer.BlockCopy(shareBytes, i * shareSize, shareData, 0, shareSize);

                        if (!TryParseHeader(shareData, out ShareHeader header, out KeySplittingFailure failure))
                        {
                            return Result<KeySplitResult, KeySplittingFailure>.Err(failure);
                        }

                        if (header.ShareCount != totalShares || header.Threshold != threshold)
                        {
                            return Result<KeySplitResult, KeySplittingFailure>.Err(
                                KeySplittingFailure.InvalidShareData("Share metadata mismatch"));
                        }

                        if (header.HasAuth != (authKeyBytes != null))
                        {
                            return Result<KeySplitResult, KeySplittingFailure>.Err(
                                KeySplittingFailure.InvalidShareData("Share auth flag mismatch"));
                        }

                        if (!seenIndices.Add(header.Index))
                        {
                            return Result<KeySplitResult, KeySplittingFailure>.Err(
                                KeySplittingFailure.InvalidShareData("Duplicate share index"));
                        }

                        ShareLocation location = (ShareLocation)((header.Index - 1) % locationCount);
                        shares[i] = new KeyShare(shareData, header.Index, location, sessionId);
                    }

                    splitResult.SetShares(shares);
                    return Result<KeySplitResult, KeySplittingFailure>.Ok(splitResult);
                }
                finally
                {
                    if (bufferPtr != IntPtr.Zero)
                    {
                        NativeSecretSharingInterop.ecliptix_buffer_free(bufferPtr);
                    }
                }
            });
        }
        finally
        {
            if (keyBytes != null)
            {
                CryptographicOperations.ZeroMemory(keyBytes);
            }

            if (authKeyBytes != null)
            {
                CryptographicOperations.ZeroMemory(authKeyBytes);
            }
        }
    }

    public async Task<Result<SodiumSecureMemoryHandle, KeySplittingFailure>> ReconstructKeyHandleAsync(
        KeyShare[] shares,
        SodiumSecureMemoryHandle? hmacKeyHandle = null)
    {
        if (shares.Length < MinimumShares)
        {
            return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Err(
                KeySplittingFailure.InsufficientShares(shares.Length, MinimumShares));
        }

        if (shares.Any(share => share.ShareData.Length == 0))
        {
            return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Err(
                KeySplittingFailure.InvalidShareData("Share data is missing"));
        }

        byte[]? authKeyBytes = null;

        try
        {
            if (hmacKeyHandle is { IsInvalid: false })
            {
                Result<byte[], SodiumFailure> hmacReadResult = hmacKeyHandle.ReadBytes(hmacKeyHandle.Length);
                if (hmacReadResult.IsErr)
                {
                    return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Err(
                        KeySplittingFailure.HmacKeyRetrievalFailed(hmacReadResult.UnwrapErr().Message));
                }

                authKeyBytes = hmacReadResult.Unwrap();
                if (authKeyBytes.Length == 0)
                {
                    authKeyBytes = null;
                }
                else if (authKeyBytes.Length != AuthKeyLength)
                {
                    return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Err(
                        KeySplittingFailure.InvalidKeyData("Auth key must be 32 bytes"));
                }
            }

            return await Task.Run(() =>
            {
                if (!TryParseHeader(shares[0].ShareData, out ShareHeader header, out KeySplittingFailure failure))
                {
                    return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Err(failure);
                }

                if (header.HasAuth != (authKeyBytes != null))
                {
                    return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Err(
                        KeySplittingFailure.InvalidShareData("Share auth flag mismatch"));
                }

                if (shares.Length < header.Threshold)
                {
                    return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Err(
                        KeySplittingFailure.InsufficientShares(shares.Length, header.Threshold));
                }

                int shareSize = shares[0].ShareData.Length;
                foreach (KeyShare share in shares)
                {
                    if (share.ShareData.Length != shareSize)
                    {
                        return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Err(
                            KeySplittingFailure.InvalidShareData("Share lengths do not match"));
                    }
                }

                if (shareSize != header.ExpectedLength)
                {
                    return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Err(
                        KeySplittingFailure.InvalidShareData("Share length does not match header"));
                }

                int totalLength = checked(shareSize * shares.Length);
                byte[] sharesBlob = new byte[totalLength];
                for (int i = 0; i < shares.Length; i++)
                {
                    Buffer.BlockCopy(shares[i].ShareData, 0, sharesBlob, i * shareSize, shareSize);
                }

                IntPtr bufferPtr = IntPtr.Zero;
                try
                {
                    bufferPtr = NativeSecretSharingInterop.ecliptix_buffer_allocate(0);
                    if (bufferPtr == IntPtr.Zero)
                    {
                        return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Err(
                            KeySplittingFailure.AllocationFailed("Failed to allocate secret buffer"));
                    }

                    NativeSecretSharingInterop.EcliptixErrorCode result =
                        NativeSecretSharingInterop.ecliptix_secret_sharing_reconstruct(
                            sharesBlob,
                            (nuint)sharesBlob.Length,
                            (nuint)shareSize,
                            (nuint)shares.Length,
                            authKeyBytes,
                            (nuint)(authKeyBytes?.Length ?? 0),
                            bufferPtr,
                            out NativeSecretSharingInterop.EcliptixError error);

                    if (result != NativeSecretSharingInterop.EcliptixErrorCode.Success)
                    {
                        string message = error.GetMessage();
                        NativeSecretSharingInterop.ecliptix_error_free(ref error);
                        return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Err(
                            MapReconstructError(result, message));
                    }

                    NativeSecretSharingInterop.EcliptixBuffer buffer =
                        Marshal.PtrToStructure<NativeSecretSharingInterop.EcliptixBuffer>(bufferPtr);
                    if (buffer.Length == 0)
                    {
                        return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Err(
                            KeySplittingFailure.KeyReconstructionFailed("Native reconstruction returned empty key"));
                    }

                    int bufferLength = checked((int)buffer.Length);
                    byte[] secretBytes = new byte[bufferLength];
                    Marshal.Copy(buffer.Data, secretBytes, 0, bufferLength);

                    Result<SodiumSecureMemoryHandle, SodiumFailure> allocateResult =
                        SodiumSecureMemoryHandle.Allocate(secretBytes.Length);
                    if (allocateResult.IsErr)
                    {
                        return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Err(
                            KeySplittingFailure.AllocationFailed(allocateResult.UnwrapErr().Message));
                    }

                    SodiumSecureMemoryHandle handle = allocateResult.Unwrap();
                    Result<Unit, SodiumFailure> writeResult = handle.Write(secretBytes);
                    if (writeResult.IsErr)
                    {
                        handle.Dispose();
                        return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Err(
                            KeySplittingFailure.MemoryWriteFailed(writeResult.UnwrapErr().Message));
                    }

                    CryptographicOperations.ZeroMemory(secretBytes);
                    return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Ok(handle);
                }
                finally
                {
                    if (bufferPtr != IntPtr.Zero)
                    {
                        NativeSecretSharingInterop.ecliptix_buffer_free(bufferPtr);
                    }
                }
            });
        }
        finally
        {
            if (authKeyBytes != null)
            {
                CryptographicOperations.ZeroMemory(authKeyBytes);
            }
        }
    }

    private static KeySplittingFailure MapSplitError(
        NativeSecretSharingInterop.EcliptixErrorCode code,
        string message)
    {
        return code switch
        {
            NativeSecretSharingInterop.EcliptixErrorCode.ErrorInvalidInput =>
                KeySplittingFailure.InvalidKeyData(message),
            NativeSecretSharingInterop.EcliptixErrorCode.ErrorOutOfMemory =>
                KeySplittingFailure.AllocationFailed(message),
            _ => KeySplittingFailure.KeySplittingFailed(message)
        };
    }

    private static KeySplittingFailure MapReconstructError(
        NativeSecretSharingInterop.EcliptixErrorCode code,
        string message)
    {
        return code switch
        {
            NativeSecretSharingInterop.EcliptixErrorCode.ErrorInvalidInput =>
                KeySplittingFailure.InvalidShareData(message),
            NativeSecretSharingInterop.EcliptixErrorCode.ErrorOutOfMemory =>
                KeySplittingFailure.AllocationFailed(message),
            _ => KeySplittingFailure.KeyReconstructionFailed(message)
        };
    }

    private static bool TryParseHeader(
        byte[] shareData,
        out ShareHeader header,
        out KeySplittingFailure failure)
    {
        header = default;
        failure = KeySplittingFailure.InvalidShareData("Invalid share header");

        if (shareData.Length < ShareHeaderSize)
        {
            failure = KeySplittingFailure.InvalidShareData("Share data is too short");
            return false;
        }

        for (int i = 0; i < ShareMagic.Length; i++)
        {
            if (shareData[i] != ShareMagic[i])
            {
                failure = KeySplittingFailure.InvalidShareData("Share magic mismatch");
                return false;
            }
        }

        byte threshold = shareData[4];
        byte shareCount = shareData[5];
        byte index = shareData[6];
        byte flags = shareData[7];
        int secretLength = (shareData[8] << 24) |
                           (shareData[9] << 16) |
                           (shareData[10] << 8) |
                           shareData[11];

        if (threshold < MinimumShares || threshold > shareCount)
        {
            failure = KeySplittingFailure.InvalidShareData("Share threshold is invalid");
            return false;
        }

        if (index == 0 || index > shareCount)
        {
            failure = KeySplittingFailure.InvalidShareData("Share index is invalid");
            return false;
        }

        if (secretLength <= 0 || secretLength > MaxKeyLength)
        {
            failure = KeySplittingFailure.InvalidShareData("Share secret length is invalid");
            return false;
        }

        bool hasAuth = (flags & 0x01) != 0;
        int expectedLength = ShareHeaderSize + secretLength + (hasAuth ? AuthTagSize : 0);
        if (shareData.Length != expectedLength)
        {
            failure = KeySplittingFailure.InvalidShareData("Share length mismatch");
            return false;
        }

        header = new ShareHeader(threshold, shareCount, index, secretLength, hasAuth, expectedLength);
        return true;
    }

    private readonly record struct ShareHeader(
        byte Threshold,
        byte ShareCount,
        byte Index,
        int SecretLength,
        bool HasAuth,
        int ExpectedLength);
}

internal static class NativeSecretSharingInterop
{
    private const string LibraryName = "epp_relay";

    internal enum EcliptixErrorCode
    {
        Success = 0,
        ErrorGeneric = 1,
        ErrorInvalidInput = 2,
        ErrorKeyGeneration = 3,
        ErrorDeriveKey = 4,
        ErrorHandshake = 5,
        ErrorEncryption = 6,
        ErrorDecryption = 7,
        ErrorDecode = 8,
        ErrorEncode = 9,
        ErrorBufferTooSmall = 10,
        ErrorObjectDisposed = 11,
        ErrorPrepareLocal = 12,
        ErrorOutOfMemory = 13,
        ErrorSodiumFailure = 14,
        ErrorNullPointer = 15,
        ErrorInvalidState = 16,
        ErrorReplayAttack = 17,
        ErrorSessionExpired = 18,
        ErrorPqMissing = 19
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct EcliptixBuffer
    {
        public IntPtr Data;
        public nuint Length;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct EcliptixError
    {
        public EcliptixErrorCode Code;
        public IntPtr Message;

        public readonly string GetMessage()
        {
            return Message != IntPtr.Zero ? Marshal.PtrToStringAnsi(Message) ?? string.Empty : string.Empty;
        }
    }

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_secret_sharing_split(
        [In] byte[] secret,
        nuint secretLength,
        byte threshold,
        byte shareCount,
        [In] byte[]? authKey,
        nuint authKeyLength,
        IntPtr outShares,
        out nuint outShareLength,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_secret_sharing_reconstruct(
        [In] byte[] shares,
        nuint sharesLength,
        nuint shareLength,
        nuint shareCount,
        [In] byte[]? authKey,
        nuint authKeyLength,
        IntPtr outSecret,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr ecliptix_buffer_allocate(nuint capacity);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void ecliptix_buffer_free(IntPtr buffer);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void ecliptix_error_free(ref EcliptixError error);
}
