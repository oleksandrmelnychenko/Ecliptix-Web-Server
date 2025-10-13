using System.Buffers;
using Ecliptix.Utilities;
using Ecliptix.Security.Opaque.Models;
using Ecliptix.Security.Opaque.Contracts;
using Ecliptix.Protobuf.Account;
using Ecliptix.Security.Opaque.Models.AuthenticationMessages;
using Ecliptix.Security.Opaque.Models.RegistrationMessages;
using Ecliptix.Security.Opaque.Failures;
using Google.Protobuf;

namespace Ecliptix.Security.Opaque.Services;

public sealed class OpaqueProtocolAdapter : IOpaqueProtocolService
{
    private const int ContextTokenSize = 64;
    private const int ServerOprfResponseSize = 32;
    private const int ServerEphemeralKeySize = 33;
    private const int MaskingKeySize = 32;
    private const int ClientRegistrationRecordSize = 176;
    private const int ServerCredentialsSize = 208;
    private const int CredentialsBaseOffset = 144;
    private const int CredentialsMaskingKeyOffset = 144;
    private const int CredentialsExportKeyOffset = 176;
    private const int ServerMacOffset = 240;
    private const int ServerMacSize = 64;
    private const int AuthTokenExpirationHours = 24;
    private const string AuthenticationSuccessful = "Authentication successful";
    private const string AuthenticationFailed = "Authentication failed";

    private readonly INativeOpaqueProtocolService _nativeService;

    public OpaqueProtocolAdapter(INativeOpaqueProtocolService nativeService)
    {
        _nativeService = nativeService;
    }

    public (byte[] Response, byte[] MaskingKey) ProcessOprfRequest(byte[] oprfRequest)
    {
        Result<RegistrationRequest, OpaqueServerFailure> registrationRequestResult =
            RegistrationRequest.Create(oprfRequest);

        if (registrationRequestResult.IsErr)
        {
            throw new InvalidOperationException(
                $"Invalid OPRF request: {registrationRequestResult.UnwrapErr().Message}");
        }

        RegistrationRequest registrationRequest = registrationRequestResult.Unwrap();
        Result<(RegistrationResponse Response, byte[] ServerCredentials), OpaqueServerFailure> result =
            _nativeService.CreateRegistrationResponse(registrationRequest);

        return result.Match(
            ok =>
            {
                Span<byte> maskingKeySpan = stackalloc byte[MaskingKeySize];
                ok.ServerCredentials.AsSpan(CredentialsMaskingKeyOffset, MaskingKeySize).CopyTo(maskingKeySpan);
                return (ok.Response.Data, maskingKeySpan.ToArray());
            },
            err => throw new InvalidOperationException($"OPRF processing failed: {err.Message}")
        );
    }

    public (byte[] Response, byte[] MaskingKey, byte[] SessionKey) ProcessOprfRequestWithSessionKey(byte[] oprfRequest)
    {
        Result<RegistrationRequest, OpaqueServerFailure> registrationRequestResult =
            RegistrationRequest.Create(oprfRequest);

        if (registrationRequestResult.IsErr)
        {
            throw new InvalidOperationException(
                $"Invalid OPRF request: {registrationRequestResult.UnwrapErr().Message}");
        }

        RegistrationRequest registrationRequest = registrationRequestResult.Unwrap();
        Result<(RegistrationResponse Response, byte[] ServerCredentials), OpaqueServerFailure> result =
            _nativeService.CreateRegistrationResponse(registrationRequest);

        return result.Match(
            ok =>
            {
                Span<byte> maskingKeySpan = stackalloc byte[MaskingKeySize];
                ok.ServerCredentials.AsSpan(CredentialsMaskingKeyOffset, MaskingKeySize).CopyTo(maskingKeySpan);

                Span<byte> sessionKeySpan = stackalloc byte[MaskingKeySize];
                ok.ServerCredentials.AsSpan(CredentialsExportKeyOffset, MaskingKeySize).CopyTo(sessionKeySpan);

                return (ok.Response.Data, maskingKeySpan.ToArray(), sessionKeySpan.ToArray());
            },
            err => throw new InvalidOperationException($"OPRF processing failed: {err.Message}")
        );
    }

    public Result<(OpaqueSignInInitResponse Response, byte[] ServerMac), OpaqueFailure> InitiateSignIn(
        OpaqueSignInInitRequest request, MembershipOpaqueQueryRecord queryRecord)
    {
        Result<KE1, OpaqueFailure> ke1ValidationResult = ValidateKe1(request);
        if (ke1ValidationResult.IsErr)
            return Result<(OpaqueSignInInitResponse, byte[]), OpaqueFailure>.Err(ke1ValidationResult.UnwrapErr());

        KE1 ke1 = ke1ValidationResult.Unwrap();
        byte[] serverCredentials =
            ConstructServerCredentials(queryRecord.RegistrationRecord, queryRecord.MaskingKey);

        Result<KE2, OpaqueServerFailure> ke2Result =
            _nativeService.GenerateKe2(ke1, serverCredentials);

        return ke2Result.Match(
            ok =>
            {
                Span<byte> serverMacSpan = stackalloc byte[ServerMacSize];
                ExtractServerMac(ok.Data, serverMacSpan);
                byte[] serverMac = serverMacSpan.ToArray();

                OpaqueSignInInitResponse response =
                    BuildSignInInitResponse(ok.Data, queryRecord.RegistrationRecord);
                return Result<(OpaqueSignInInitResponse, byte[]), OpaqueFailure>.Ok((response, serverMac));
            },
            err => Result<(OpaqueSignInInitResponse, byte[]), OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput($"KE2 generation failed: {err.Message}")));
    }

    public Result<(SodiumSecureMemoryHandle SessionKeyHandle, OpaqueSignInFinalizeResponse Response), OpaqueFailure> CompleteSignIn(
        OpaqueSignInFinalizeRequest request,
        byte[] serverMac)
    {
        Result<KE3, OpaqueFailure> ke3ValidationResult = ValidateKe3(request);
        if (ke3ValidationResult.IsErr)
            return Result<(SodiumSecureMemoryHandle, OpaqueSignInFinalizeResponse), OpaqueFailure>.Err(ke3ValidationResult.UnwrapErr());

        KE3 ke3 = ke3ValidationResult.Unwrap();

        Result<SodiumSecureMemoryHandle, OpaqueServerFailure> sessionKeyResult =
            _nativeService.FinishAuthentication(ke3);

        return sessionKeyResult.Match(
            ok => Result<(SodiumSecureMemoryHandle, OpaqueSignInFinalizeResponse), OpaqueFailure>.Ok(
                (ok, BuildSuccessfulFinalizeResponse(serverMac))),
            err => Result<(SodiumSecureMemoryHandle, OpaqueSignInFinalizeResponse), OpaqueFailure>.Ok(
                (null!, BuildFailedFinalizeResponse()))
        );
    }

    public Result<byte[], OpaqueFailure> CompleteRegistrationWithSessionKey(byte[] peerRegistrationRecord)
    {
        try
        {
            Result<RegistrationRequest, OpaqueServerFailure> registrationRequestResult =
                RegistrationRequest.Create(peerRegistrationRecord);

            if (registrationRequestResult.IsErr)
            {
                return Result<byte[], OpaqueFailure>.Err(
                    OpaqueFailure.InvalidInput($"Invalid registration record: {registrationRequestResult.UnwrapErr().Message}"));
            }

            RegistrationRequest registrationRequest = registrationRequestResult.Unwrap();
            Result<(RegistrationResponse Response, byte[] ServerCredentials), OpaqueServerFailure> result =
                _nativeService.CreateRegistrationResponse(registrationRequest);

            return result.Match(
                ok =>
                {
                    ReadOnlySpan<byte> exportKeySpan = ok.ServerCredentials.AsSpan(CredentialsExportKeyOffset, MaskingKeySize);
                    byte[] sessionKey = exportKeySpan.ToArray();
                    return Result<byte[], OpaqueFailure>.Ok(sessionKey);
                },
                err => Result<byte[], OpaqueFailure>.Err(
                    OpaqueFailure.InvalidInput($"Registration completion failed: {err.Message}"))
            );
        }
        catch (Exception ex)
        {
            return Result<byte[], OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput($"Registration completion failed: {ex.Message}"));
        }
    }

    private static Result<KE1, OpaqueFailure> ValidateKe1(OpaqueSignInInitRequest request)
    {
        Result<KE1, OpaqueServerFailure> ke1Result = KE1.Create(request.PeerOprf.ToByteArray());
        return ke1Result.IsErr
            ? Result<KE1, OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput($"Invalid KE1: {ke1Result.UnwrapErr().Message}"))
            : Result<KE1, OpaqueFailure>.Ok(ke1Result.Unwrap());
    }

    private static Result<KE3, OpaqueFailure> ValidateKe3(OpaqueSignInFinalizeRequest request)
    {
        Result<KE3, OpaqueServerFailure> ke3Result = KE3.Create(request.ClientMac.ToByteArray());
        return ke3Result.IsErr
            ? Result<KE3, OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput($"Invalid KE3: {ke3Result.UnwrapErr().Message}"))
            : Result<KE3, OpaqueFailure>.Ok(ke3Result.Unwrap());
    }

    private static OpaqueSignInInitResponse BuildSignInInitResponse(byte[] ke2Data, byte[] registrationRecord)
    {
        ReadOnlySpan<byte> ke2Span = ke2Data.AsSpan();

        Span<byte> serverOprfResponseBuffer = stackalloc byte[ServerOprfResponseSize];
        Span<byte> serverEphemeralKeyBuffer = stackalloc byte[ServerEphemeralKeySize];

        ke2Span[..ServerOprfResponseSize].CopyTo(serverOprfResponseBuffer);
        ke2Span.Slice(ServerOprfResponseSize, ServerEphemeralKeySize).CopyTo(serverEphemeralKeyBuffer);

        return new OpaqueSignInInitResponse
        {
            ServerOprfResponse = ByteString.CopyFrom(serverOprfResponseBuffer),
            ServerEphemeralPublicKey = ByteString.CopyFrom(serverEphemeralKeyBuffer),
            RegistrationRecord = ByteString.CopyFrom(registrationRecord),
            ServerStateToken = ByteString.CopyFrom(ke2Data),
            Result = OpaqueSignInInitResponse.Types.SignInResult.Succeeded
        };
    }

    private static void ExtractServerMac(ReadOnlySpan<byte> ke2Data, Span<byte> destination)
    {
        ke2Data.Slice(ServerMacOffset, ServerMacSize).CopyTo(destination);
    }

    private static OpaqueSignInFinalizeResponse BuildSuccessfulFinalizeResponse(byte[] serverMac)
    {
        return new OpaqueSignInFinalizeResponse
        {
            ServerMac = ByteString.CopyFrom(serverMac),
            Result = OpaqueSignInFinalizeResponse.Types.SignInResult.Succeeded,
            Message = AuthenticationSuccessful
        };
    }

    private static OpaqueSignInFinalizeResponse BuildFailedFinalizeResponse()
    {
        return new OpaqueSignInFinalizeResponse
        {
            Result = OpaqueSignInFinalizeResponse.Types.SignInResult.InvalidCredentials,
            Message = AuthenticationFailed
        };
    }

    private static byte[] ConstructServerCredentials(byte[] clientRegistrationRecord, byte[] maskingKey)
    {
        if (clientRegistrationRecord.Length != ClientRegistrationRecordSize)
            throw new ArgumentException(
                $"Client registration record must be {ClientRegistrationRecordSize} bytes, got {clientRegistrationRecord.Length}");
        if (maskingKey.Length != MaskingKeySize)
            throw new ArgumentException($"Masking key must be {MaskingKeySize} bytes, got {maskingKey.Length}");

        byte[] credentials = ArrayPool<byte>.Shared.Rent(ServerCredentialsSize);
        try
        {
            Span<byte> credentialsSpan = credentials.AsSpan(0, ServerCredentialsSize);
            ReadOnlySpan<byte> recordSpan = clientRegistrationRecord.AsSpan();
            ReadOnlySpan<byte> maskingKeySpan = maskingKey.AsSpan();

            recordSpan[..CredentialsBaseOffset].CopyTo(credentialsSpan.Slice(0, CredentialsBaseOffset));
            maskingKeySpan.CopyTo(credentialsSpan.Slice(CredentialsMaskingKeyOffset, MaskingKeySize));
            recordSpan.Slice(CredentialsBaseOffset, MaskingKeySize).CopyTo(
                credentialsSpan.Slice(CredentialsExportKeyOffset, MaskingKeySize));

            byte[] result = new byte[ServerCredentialsSize];
            credentialsSpan.CopyTo(result);
            return result;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(credentials, clearArray: true);
        }
    }
}
