using System;
using System.Runtime.InteropServices;

namespace Ecliptix.SecureProtocol.Domain.ProtocolNative;

internal static class NativeInterop
{
    private const string LibraryName = "epp_relay";

    internal enum EppErrorCode
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

    internal enum EppEnvelopeType
    {
        Request = 0,
        Response = 1,
        Notification = 2,
        Heartbeat = 3,
        ErrorResponse = 4
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct EppBuffer
    {
        public IntPtr Data;
        public nuint Length;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct EppError
    {
        public EppErrorCode Code;
        public IntPtr Message;

        public readonly string GetMessage()
        {
            return Message != IntPtr.Zero ? Marshal.PtrToStringAnsi(Message) ?? string.Empty : string.Empty;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct EppSessionConfig
    {
        public uint MaxMessagesPerChain;
    }

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    internal static extern IntPtr epp_version();

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_init();

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void epp_shutdown();

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_identity_create(
        out IntPtr outHandle,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_identity_create_from_seed(
        [In] byte[] seed,
        nuint seedLength,
        out IntPtr outHandle,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    internal static extern EppErrorCode epp_identity_create_with_context(
        [In] byte[] seed,
        nuint seedLength,
        string membershipId,
        nuint membershipIdLength,
        out IntPtr outHandle,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_identity_get_x25519_public(
        IntPtr handle,
        [Out] byte[] outKey,
        nuint outKeyLength,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_identity_get_ed25519_public(
        IntPtr handle,
        [Out] byte[] outKey,
        nuint outKeyLength,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_identity_get_kyber_public(
        IntPtr handle,
        [Out] byte[] outKey,
        nuint outKeyLength,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void epp_identity_destroy(IntPtr handle);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_prekey_bundle_create(
        IntPtr identityKeys,
        out EppBuffer outBundle,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_handshake_responder_start(
        IntPtr identityKeys,
        [In] byte[] localPrekeyBundle,
        nuint localPrekeyBundleLength,
        [In] byte[] handshakeInit,
        nuint handshakeInitLength,
        ref EppSessionConfig config,
        out IntPtr outHandle,
        out EppBuffer outHandshakeAck,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_handshake_responder_finish(
        IntPtr handle,
        out IntPtr outSession,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void epp_handshake_responder_destroy(IntPtr handle);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_session_encrypt(
        IntPtr handle,
        [In] byte[] plaintext,
        nuint plaintextLength,
        EppEnvelopeType envelopeType,
        uint envelopeId,
        [In] byte[]? correlationId,
        nuint correlationIdLength,
        out EppBuffer outEncryptedEnvelope,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_session_decrypt(
        IntPtr handle,
        [In] byte[] encryptedEnvelope,
        nuint encryptedEnvelopeLength,
        out EppBuffer outPlaintext,
        out EppBuffer outMetadata,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_session_serialize(
        IntPtr handle,
        out EppBuffer outState,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_session_deserialize(
        [In] byte[] stateBytes,
        nuint stateBytesLength,
        out IntPtr outHandle,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void epp_session_destroy(IntPtr handle);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_envelope_validate(
        [In] byte[] encryptedEnvelope,
        nuint encryptedEnvelopeLength,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_derive_root_key(
        [In] byte[] opaqueSessionKey,
        nuint opaqueSessionKeyLength,
        [In] byte[] userContext,
        nuint userContextLength,
        [Out] byte[] outRootKey,
        nuint outRootKeyLength,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_shamir_split(
        [In] byte[] secret,
        nuint secretLength,
        byte threshold,
        byte shareCount,
        [In] byte[] authKey,
        nuint authKeyLength,
        out EppBuffer outShares,
        out nuint outShareLength,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_shamir_reconstruct(
        [In] byte[] shares,
        nuint sharesLength,
        nuint shareLength,
        nuint shareCount,
        [In] byte[] authKey,
        nuint authKeyLength,
        out EppBuffer outSecret,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void epp_buffer_release(ref EppBuffer buffer);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr epp_buffer_alloc(nuint capacity);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void epp_buffer_free(IntPtr buffer);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void epp_error_free(ref EppError error);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr epp_error_string(EppErrorCode code);

    internal static string GetVersion() => Marshal.PtrToStringAnsi(epp_version()) ?? "unknown";

    internal static string ErrorCodeToString(EppErrorCode code)
    {
        IntPtr messagePtr = epp_error_string(code);
        return Marshal.PtrToStringAnsi(messagePtr) ?? "unknown error";
    }
}
