using System;
using System.Buffers;
using Ecliptix.OPAQUE.Server;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Security.Opaque.Contracts;
using Ecliptix.Security.Opaque.Failures;
using Ecliptix.Security.Opaque.Models;
using Ecliptix.Security.Opaque.Models.AuthenticationMessages;
using Ecliptix.Security.Opaque.Models.RegistrationMessages;
using Ecliptix.Utilities;
using Google.Protobuf;
using Serilog;
using Serilog.Events;

namespace Ecliptix.Security.Opaque.Services;

public sealed class OpaqueProtocolAdapter(IOpaqueKeyRingService keyRingService) : IOpaqueProtocolService
{
    private const int ServerOprfResponseSize = OpaqueConstants.PUBLIC_KEY_LENGTH;
    private const int ServerEphemeralKeySize = OpaqueConstants.PUBLIC_KEY_LENGTH;
    private const int SessionKeyLength = OpaqueConstants.HASH_LENGTH;
    private const int ClientRegistrationRecordSize = OpaqueConstants.REGISTRATION_RECORD_LENGTH;
    private const int ServerCredentialsSize = OpaqueConstants.SERVER_CREDENTIALS_LENGTH;
    private const int ServerMacOffset = OpaqueConstants.NONCE_LENGTH + OpaqueConstants.PUBLIC_KEY_LENGTH + OpaqueConstants.CREDENTIAL_RESPONSE_LENGTH;
    private const int ServerMacSize = OpaqueConstants.MAC_LENGTH;
    private const int ServerEphemeralKeyOffset = OpaqueConstants.NONCE_LENGTH;
    private const int ServerOprfResponseOffset = OpaqueConstants.NONCE_LENGTH + OpaqueConstants.PUBLIC_KEY_LENGTH;
    private const string AuthenticationSuccessful = "Authentication successful";
    private const string AuthenticationFailed = "Authentication failed";

    public (byte[] Response, Guid AccountId, int KeyVersion) ProcessOprfRequest(byte[] oprfRequest, Guid accountId)
    {
        ArgumentNullException.ThrowIfNull(oprfRequest);

        int keyVersion = keyRingService.ActiveKeyVersion;
        if (Log.IsEnabled(LogEventLevel.Debug))
        {
            Log.Debug(
                "[OPAQUE-OPRF] Request accountId={AccountId} length={Length} data={Data}",
                accountId,
                oprfRequest.Length,
                oprfRequest.Length > 0 ? Convert.ToHexString(oprfRequest) : string.Empty);
        }

        Result<RegistrationRequest, OpaqueServerFailure> registrationRequestResult =
            RegistrationRequest.Create(oprfRequest);

        if (registrationRequestResult.IsErr)
        {
            throw new InvalidOperationException(
                $"Invalid OPRF request: {registrationRequestResult.UnwrapErr().Message}");
        }

        RegistrationRequest registrationRequest = registrationRequestResult.Unwrap();
        Result<RegistrationResponse, OpaqueServerFailure> result =
            keyRingService.CreateRegistrationResponse(registrationRequest, accountId, keyVersion);

        return result.Match(
            ok =>
            {
                if (Log.IsEnabled(LogEventLevel.Debug))
                {
                    Log.Debug(
                        "[OPAQUE-OPRF] Response accountId={AccountId} length={Length} data={Data}",
                        accountId,
                        ok.Data.Length,
                        Convert.ToHexString(ok.Data));
                }
                return (ok.Data, accountId, keyVersion);
            },
            err => throw new InvalidOperationException($"OPRF processing failed: {err.Message}")
        );
    }

    public (byte[] Response, Guid AccountId, byte[] SessionKey, int KeyVersion) ProcessOprfRequestWithSessionKey(
        byte[] oprfRequest,
        Guid accountId)
    {
        ArgumentNullException.ThrowIfNull(oprfRequest);

        int keyVersion = keyRingService.ActiveKeyVersion;
        if (Log.IsEnabled(LogEventLevel.Debug))
        {
            Log.Debug(
                "[OPAQUE-OPRF] Request+SessionKey accountId={AccountId} length={Length} data={Data}",
                accountId,
                oprfRequest.Length,
                oprfRequest.Length > 0 ? Convert.ToHexString(oprfRequest) : string.Empty);
        }

        Result<RegistrationRequest, OpaqueServerFailure> registrationRequestResult =
            RegistrationRequest.Create(oprfRequest);

        if (registrationRequestResult.IsErr)
        {
            throw new InvalidOperationException(
                $"Invalid OPRF request: {registrationRequestResult.UnwrapErr().Message}");
        }

        RegistrationRequest registrationRequest = registrationRequestResult.Unwrap();
        Result<RegistrationResponse, OpaqueServerFailure> result =
            keyRingService.CreateRegistrationResponse(registrationRequest, accountId, keyVersion);

        return result.Match(
            ok =>
            {
                if (Log.IsEnabled(LogEventLevel.Debug))
                {
                    Log.Debug(
                        "[OPAQUE-OPRF] Response+SessionKey accountId={AccountId} length={Length} data={Data}",
                        accountId,
                        ok.Data.Length,
                        Convert.ToHexString(ok.Data));
                }
                byte[] sessionKeyPlaceholder = new byte[SessionKeyLength];
                return (ok.Data, accountId, sessionKeyPlaceholder, keyVersion);
            },
            err => throw new InvalidOperationException($"OPRF processing failed: {err.Message}")
        );
    }

    public Result<(OpaqueSignInInitResponse Response, byte[] ServerMac), OpaqueFailure> InitiateSignIn(
        OpaqueSignInInitRequest request, MembershipOpaqueQueryRecord queryRecord)
    {
        ArgumentNullException.ThrowIfNull(queryRecord.RegistrationRecord);

        Result<KE1, OpaqueFailure> ke1ValidationResult = ValidateKe1(request);
        if (ke1ValidationResult.IsErr)
        {
            return Result<(OpaqueSignInInitResponse, byte[]), OpaqueFailure>.Err(ke1ValidationResult.UnwrapErr());
        }

        KE1 ke1 = ke1ValidationResult.Unwrap();
        byte[] registrationRecord = queryRecord.RegistrationRecord;
        if (Log.IsEnabled(LogEventLevel.Debug))
        {
            Log.Debug(
                "[OPAQUE-SIGNIN-INIT] accountId={AccountId} ke1Len={Length} ke1={Data} recordLen={RecordLen} record={Record}",
                queryRecord.AccountId,
                ke1.Data.Length,
                Convert.ToHexString(ke1.Data),
                registrationRecord.Length,
                registrationRecord.Length > 0
                    ? Convert.ToHexString(registrationRecord)
                    : string.Empty);
        }

        byte[] serverCredentials = ConstructServerCredentials(registrationRecord);

        Result<KE2, OpaqueServerFailure> ke2Result =
            keyRingService.GenerateKe2(ke1, queryRecord.AccountId, serverCredentials, queryRecord.OpaqueKeyVersion);

        return ke2Result.Match(
            ok =>
            {
                Span<byte> serverMacSpan = stackalloc byte[ServerMacSize];
                ExtractServerMac(ok.Data, serverMacSpan);
                byte[] serverMac = serverMacSpan.ToArray();

                if (Log.IsEnabled(LogEventLevel.Debug))
                {
                    Log.Debug(
                        "[OPAQUE-SIGNIN-INIT] accountId={AccountId} ke2Len={Length} ke2={Data} serverMac={ServerMac}",
                        queryRecord.AccountId,
                        ok.Data.Length,
                        Convert.ToHexString(ok.Data),
                        Convert.ToHexString(serverMac));
                }

                OpaqueSignInInitResponse response =
                    BuildSignInInitResponse(ok.Data, registrationRecord);
                return Result<(OpaqueSignInInitResponse, byte[]), OpaqueFailure>.Ok((response, serverMac));
            },
            err => Result<(OpaqueSignInInitResponse, byte[]), OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput($"KE2 generation failed: {err.Message}")));
    }

    public Result<(SodiumSecureMemoryHandle SessionKeyHandle, OpaqueSignInFinalizeResponse Response), OpaqueFailure> CompleteSignIn(
        OpaqueSignInFinalizeRequest request,
        byte[]? serverMac,
        int keyVersion)
    {
        if (serverMac is null)
        {
            return Result<(SodiumSecureMemoryHandle, OpaqueSignInFinalizeResponse), OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput("Server MAC is required for sign-in finalization."));
        }

        Result<KE3, OpaqueFailure> ke3ValidationResult = ValidateKe3(request);
        if (ke3ValidationResult.IsErr)
        {
            return Result<(SodiumSecureMemoryHandle, OpaqueSignInFinalizeResponse), OpaqueFailure>.Err(ke3ValidationResult.UnwrapErr());
        }

        KE3 ke3 = ke3ValidationResult.Unwrap();
        if (Log.IsEnabled(LogEventLevel.Debug))
        {
            Log.Debug(
                "[OPAQUE-SIGNIN-FINAL] ke3Len={Length} ke3={Data} serverMacLen={ServerMacLen} serverMac={ServerMac}",
                ke3.Data.Length,
                Convert.ToHexString(ke3.Data),
                serverMac.Length,
                serverMac.Length > 0 ? Convert.ToHexString(serverMac) : string.Empty);
        }

        Result<SodiumSecureMemoryHandle, OpaqueServerFailure> sessionKeyResult =
            keyRingService.FinishAuthentication(ke3, keyVersion);

        return sessionKeyResult.Match(
            ok => Result<(SodiumSecureMemoryHandle, OpaqueSignInFinalizeResponse), OpaqueFailure>.Ok(
                (ok, BuildSuccessfulFinalizeResponse(serverMac))),
            _ => Result<(SodiumSecureMemoryHandle, OpaqueSignInFinalizeResponse), OpaqueFailure>.Ok(
                (null!, BuildFailedFinalizeResponse()))
        );
    }

    public Result<(SodiumSecureMemoryHandle SessionKeyHandle, SodiumSecureMemoryHandle MasterKeyHandle, OpaqueSignInFinalizeResponse Response), OpaqueFailure>
        CompleteSignInWithMasterKey(OpaqueSignInFinalizeRequest request, byte[]? serverMac, int keyVersion)
    {
        if (serverMac is null)
        {
            return Result<(SodiumSecureMemoryHandle, SodiumSecureMemoryHandle, OpaqueSignInFinalizeResponse), OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput("Server MAC is required for sign-in finalization."));
        }

        Result<KE3, OpaqueFailure> ke3ValidationResult = ValidateKe3(request);
        if (ke3ValidationResult.IsErr)
        {
            return Result<(SodiumSecureMemoryHandle, SodiumSecureMemoryHandle, OpaqueSignInFinalizeResponse), OpaqueFailure>.Err(
                ke3ValidationResult.UnwrapErr());
        }

        KE3 ke3 = ke3ValidationResult.Unwrap();
        if (Log.IsEnabled(LogEventLevel.Debug))
        {
            Log.Debug(
                "[OPAQUE-SIGNIN-FINAL] ke3Len={Length} ke3={Data} serverMacLen={ServerMacLen} serverMac={ServerMac}",
                ke3.Data.Length,
                Convert.ToHexString(ke3.Data),
                serverMac.Length,
                serverMac.Length > 0 ? Convert.ToHexString(serverMac) : string.Empty);
        }

        Result<(SodiumSecureMemoryHandle SessionKey, SodiumSecureMemoryHandle MasterKey), OpaqueServerFailure> result =
            keyRingService.FinishAuthenticationWithMasterKey(ke3, keyVersion);

        return result.Match(
            ok => Result<(SodiumSecureMemoryHandle, SodiumSecureMemoryHandle, OpaqueSignInFinalizeResponse), OpaqueFailure>.Ok(
                (ok.SessionKey, ok.MasterKey, BuildSuccessfulFinalizeResponse(serverMac))),
            _ => Result<(SodiumSecureMemoryHandle, SodiumSecureMemoryHandle, OpaqueSignInFinalizeResponse), OpaqueFailure>.Ok(
                (null!, null!, BuildFailedFinalizeResponse()))
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
            return Result<byte[], OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput("Registration export key is no longer available in OPAQUE registration"));
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

        ke2Span.Slice(ServerEphemeralKeyOffset, ServerEphemeralKeySize).CopyTo(serverEphemeralKeyBuffer);
        ke2Span.Slice(ServerOprfResponseOffset, ServerOprfResponseSize).CopyTo(serverOprfResponseBuffer);

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

    private static byte[] ConstructServerCredentials(byte[] clientRegistrationRecord)
    {
        ArgumentNullException.ThrowIfNull(clientRegistrationRecord);

        if (clientRegistrationRecord.Length != ClientRegistrationRecordSize)
        {
            throw new ArgumentException(
                $"Client registration record must be {ClientRegistrationRecordSize} bytes, got {clientRegistrationRecord.Length}");
        }

        byte[] credentials = ArrayPool<byte>.Shared.Rent(ServerCredentialsSize);
        try
        {
            Span<byte> credentialsSpan = credentials.AsSpan(0, ServerCredentialsSize);
            ReadOnlySpan<byte> recordSpan = clientRegistrationRecord.AsSpan();
            recordSpan.CopyTo(credentialsSpan);

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
