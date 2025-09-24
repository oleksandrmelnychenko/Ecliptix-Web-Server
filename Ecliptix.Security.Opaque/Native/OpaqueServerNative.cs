using System.Runtime.InteropServices;

namespace Ecliptix.Security.Opaque.Native;

internal static class OpaqueServerNative
{
    private const string ServerLibrary = "libopaque_server";

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_keypair_generate(out nint handle);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern void opaque_server_keypair_destroy(nint handle);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_keypair_get_public_key(
        nint handle,
        [Out] byte[] public_key,
        nuint key_buffer_size);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_create(
        nint keypair_handle,
        out nint handle);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern void opaque_server_destroy(nint handle);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_state_create(out nint handle);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern void opaque_server_state_destroy(nint handle);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_create_registration_response(
        nint server_handle,
        [In] byte[] request_data,
        nuint request_length,
        [Out] byte[] response_data,
        nuint response_buffer_size,
        [Out] byte[] credentials_data,
        nuint credentials_buffer_size);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_generate_ke2(
        nint server_handle,
        [In] byte[] ke1_data,
        nuint ke1_length,
        [In] byte[] credentials_data,
        nuint credentials_length,
        [Out] byte[] ke2_data,
        nuint ke2_buffer_size,
        nint state_handle);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_finish(
        nint server_handle,
        [In] byte[] ke3_data,
        nuint ke3_length,
        nint state_handle,
        [Out] byte[] session_key,
        nuint session_key_buffer_size);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_credential_store_create(out nint handle);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern void opaque_credential_store_destroy(nint handle);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_credential_store_store(
        nint store_handle,
        [In] byte[] user_id,
        nuint user_id_length,
        [In] byte[] credentials_data,
        nuint credentials_length);

    [DllImport(ServerLibrary, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_credential_store_retrieve(
        nint store_handle,
        [In] byte[] user_id,
        nuint user_id_length,
        [Out] byte[] credentials_data,
        nuint credentials_buffer_size);
}