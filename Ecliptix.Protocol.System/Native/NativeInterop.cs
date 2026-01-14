using System;
using System.Runtime.InteropServices;

namespace Ecliptix.Protocol.System.Native;

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

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void EppEventCallback(uint connectionId, IntPtr userData);

    [StructLayout(LayoutKind.Sequential)]
    internal struct EppCallbacks
    {
        public EppEventCallback? OnProtocolStateChanged;
        public IntPtr UserData;
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
    internal static extern EppErrorCode epp_server_create(
        IntPtr identityKeys,
        out IntPtr outHandle,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_server_set_callbacks(
        IntPtr handle,
        in EppCallbacks callbacks,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_server_begin_handshake(
        IntPtr handle,
        uint connectionId,
        byte exchangeType,
        IntPtr outHandshakeMessage,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_server_begin_handshake_with_peer_kyber(
        IntPtr handle,
        uint connectionId,
        byte exchangeType,
        [In] byte[] peerKyberPublicKey,
        nuint peerKyberPublicKeyLength,
        IntPtr outHandshakeMessage,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_server_complete_handshake(
        IntPtr handle,
        [In] byte[] peerHandshakeMessage,
        nuint peerHandshakeMessageLength,
        [In] byte[] rootKey,
        nuint rootKeyLength,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_server_complete_handshake_auto(
        IntPtr handle,
        [In] byte[] peerHandshakeMessage,
        nuint peerHandshakeMessageLength,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_server_encrypt(
        IntPtr handle,
        [In] byte[] plaintext,
        nuint plaintextLength,
        IntPtr outEncryptedEnvelope,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_server_decrypt(
        IntPtr handle,
        [In] byte[] encryptedEnvelope,
        nuint encryptedEnvelopeLength,
        IntPtr outPlaintext,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_server_is_established(
        IntPtr handle,
        out bool outHasConnection,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_server_get_id(
        IntPtr handle,
        out uint outConnectionId,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_server_get_chain_indices(
        IntPtr handle,
        out uint outSendingIndex,
        out uint outReceivingIndex,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_server_get_used_prekey_id(
        IntPtr handle,
        [MarshalAs(UnmanagedType.I1)] out bool outHasOpkId,
        out uint outOpkId,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_server_create_from_root(
        IntPtr identityKeys,
        [In] byte[] rootKey,
        nuint rootKeyLength,
        [In] byte[] peerBundle,
        nuint peerBundleLength,
        [MarshalAs(UnmanagedType.I1)] bool isInitiator,
        out IntPtr outHandle,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_server_serialize(
        IntPtr handle,
        IntPtr outState,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_server_deserialize(
        IntPtr identityKeys,
        [In] byte[] stateBytes,
        nuint stateBytesLength,
        out IntPtr outHandle,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_server_set_kyber_secrets(
        IntPtr handle,
        [In] byte[] kyberCiphertext,
        nuint kyberCiphertextLength,
        [In] byte[] kyberSharedSecret,
        nuint kyberSharedSecretLength,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_session_age_seconds(
        IntPtr handle,
        out ulong outAgeSeconds,
        out EppError outError);

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
        [In] byte[]? authKey,
        nuint authKeyLength,
        IntPtr outShares,
        out nuint outShareLength,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EppErrorCode epp_shamir_reconstruct(
        [In] byte[] shares,
        nuint sharesLength,
        nuint shareLength,
        nuint shareCount,
        [In] byte[]? authKey,
        nuint authKeyLength,
        IntPtr outSecret,
        out EppError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void epp_server_destroy(IntPtr handle);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr epp_buffer_alloc(nuint capacity);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void epp_buffer_free(IntPtr buffer);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void epp_error_free(ref EppError error);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    internal static extern IntPtr epp_error_string(EppErrorCode code);

    internal static string GetVersion() => Marshal.PtrToStringAnsi(epp_version()) ?? "unknown";

    internal static string ErrorCodeToString(EppErrorCode code)
    {
        IntPtr messagePtr = epp_error_string(code);
        return Marshal.PtrToStringAnsi(messagePtr) ?? "unknown error";
    }
}
