using System;
using System.Runtime.InteropServices;

namespace Ecliptix.SecureProtocol.Domain.ProtocolNative;

/// <summary>
/// P/Invoke bindings that match the exported symbols from the server native library
/// (libecliptix_protocol_server).
/// </summary>
internal static class NativeInterop
{
    private const string LibraryName = "ecliptix_protocol_server";

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

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void EcliptixProtocolEventCallback(uint connectionId, IntPtr userData);

    [StructLayout(LayoutKind.Sequential)]
    internal struct EcliptixCallbacks
    {
        public EcliptixProtocolEventCallback? OnProtocolStateChanged;
        public IntPtr UserData;
    }

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    internal static extern IntPtr ecliptix_get_version();

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_initialize();

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void ecliptix_shutdown();

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_identity_keys_create(
        out IntPtr outHandle,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_identity_keys_create_from_seed(
        [In] byte[] seed,
        nuint seedLength,
        out IntPtr outHandle,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    internal static extern EcliptixErrorCode ecliptix_identity_keys_create_from_seed_with_context(
        [In] byte[] seed,
        nuint seedLength,
        string membershipId,
        nuint membershipIdLength,
        out IntPtr outHandle,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_identity_keys_get_public_x25519(
        IntPtr handle,
        [Out] byte[] outKey,
        nuint outKeyLength,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_identity_keys_get_public_ed25519(
        IntPtr handle,
        [Out] byte[] outKey,
        nuint outKeyLength,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_identity_keys_get_public_kyber(
        IntPtr handle,
        [Out] byte[] outKey,
        nuint outKeyLength,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void ecliptix_identity_keys_destroy(IntPtr handle);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_protocol_server_system_create(
        IntPtr identityKeys,
        out IntPtr outHandle,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_protocol_server_system_create_from_root(
        IntPtr identityKeys,
        [In] byte[] rootKey,
        nuint rootKeyLength,
        [In] byte[] peerBundle,
        nuint peerBundleLength,
        [MarshalAs(UnmanagedType.I1)] bool isInitiator,
        out IntPtr outHandle,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_protocol_server_system_import_state(
        IntPtr identityKeys,
        [In] byte[] stateBytes,
        nuint stateBytesLength,
        out IntPtr outHandle,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_protocol_server_system_set_callbacks(
        IntPtr handle,
        in EcliptixCallbacks callbacks,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_protocol_server_system_begin_handshake(
        IntPtr handle,
        uint connectionId,
        byte exchangeType,
        IntPtr outHandshakeMessage,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_protocol_server_system_begin_handshake_with_peer_kyber(
        IntPtr handle,
        uint connectionId,
        byte exchangeType,
        [In] byte[] peerKyberPublicKey,
        nuint peerKyberPublicKeyLength,
        IntPtr outHandshakeMessage,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_protocol_server_system_complete_handshake(
        IntPtr handle,
        [In] byte[] peerHandshakeMessage,
        nuint peerHandshakeMessageLength,
        [In] byte[] rootKey,
        nuint rootKeyLength,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_protocol_server_system_complete_handshake_auto(
        IntPtr handle,
        [In] byte[] peerHandshakeMessage,
        nuint peerHandshakeMessageLength,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_protocol_server_system_send_message(
        IntPtr handle,
        [In] byte[] plaintext,
        nuint plaintextLength,
        IntPtr outEncryptedEnvelope,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_protocol_server_system_receive_message(
        IntPtr handle,
        [In] byte[] encryptedEnvelope,
        nuint encryptedEnvelopeLength,
        IntPtr outPlaintext,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_protocol_server_system_has_connection(
        IntPtr handle,
        out bool outHasConnection,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_protocol_server_system_get_connection_id(
        IntPtr handle,
        out uint outConnectionId,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_protocol_server_system_get_selected_opk_id(
        IntPtr handle,
        [MarshalAs(UnmanagedType.I1)] out bool outHasOpkId,
        out uint outOpkId,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_protocol_server_system_export_state(
        IntPtr handle,
        IntPtr outState,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_protocol_server_system_set_kyber_secrets(
        IntPtr handle,
        [In] byte[] kyberCiphertext,
        nuint kyberCiphertextLength,
        [In] byte[] kyberSharedSecret,
        nuint kyberSharedSecretLength,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_connection_get_session_age_seconds(
        IntPtr handle,
        out ulong outAgeSeconds,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_envelope_validate_hybrid_requirements(
        [In] byte[] encryptedEnvelope,
        nuint encryptedEnvelopeLength,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern EcliptixErrorCode ecliptix_derive_root_from_opaque_session_key(
        [In] byte[] opaqueSessionKey,
        nuint opaqueSessionKeyLength,
        [In] byte[] userContext,
        nuint userContextLength,
        [Out] byte[] outRootKey,
        nuint outRootKeyLength,
        out EcliptixError outError);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void ecliptix_protocol_server_system_destroy(IntPtr handle);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr ecliptix_buffer_allocate(nuint capacity);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void ecliptix_buffer_free(IntPtr buffer);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void ecliptix_error_free(ref EcliptixError error);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    internal static extern IntPtr ecliptix_error_code_to_string(EcliptixErrorCode code);

    internal static string ErrorCodeToString(EcliptixErrorCode code)
    {
        IntPtr messagePtr = ecliptix_error_code_to_string(code);
        return Marshal.PtrToStringAnsi(messagePtr) ?? "unknown error";
    }
}
