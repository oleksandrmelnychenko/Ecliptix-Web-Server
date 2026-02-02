using System.Buffers;
using Ecliptix.OPAQUE.Relay;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Security.Opaque.Contracts;
using Ecliptix.Security.Opaque.Failures;
using Ecliptix.Security.Opaque.Models;
using Ecliptix.Security.Opaque.Models.AuthenticationMessages;
using Ecliptix.Security.Opaque.Models.RegistrationMessages;
using Ecliptix.SharedKernel;
using Google.Protobuf;
using Serilog;
using Serilog.Events;

namespace Ecliptix.Security.Opaque.Services;

public sealed class OpaqueProtocolAdapter(IOpaqueKeyRingService keyRingService) : IOpaqueProtocolService
{
    private const int RelayOprfResponseSize = OpaqueConstants.PUBLIC_KEY_LENGTH;
    private const int RelayEphemeralKeySize = OpaqueConstants.PUBLIC_KEY_LENGTH;
    private const int AgentRegistrationRecordSize = OpaqueConstants.REGISTRATION_RECORD_LENGTH;
    private const int RelayCredentialsSize = OpaqueConstants.RELAY_CREDENTIALS_LENGTH;
    private const int RelayMacOffset = OpaqueConstants.NONCE_LENGTH + OpaqueConstants.PUBLIC_KEY_LENGTH + OpaqueConstants.CREDENTIAL_RESPONSE_LENGTH;
    private const int RelayMacSize = OpaqueConstants.MAC_LENGTH;
    private const int RelayEphemeralKeyOffset = OpaqueConstants.NONCE_LENGTH;
    private const int RelayOprfResponseOffset = OpaqueConstants.NONCE_LENGTH + OpaqueConstants.PUBLIC_KEY_LENGTH;
    private const string AuthenticationSuccessful = "Authentication successful";
    private const string AuthenticationFailed = "Authentication failed";

    public (byte[] Response, int KeyVersion) ProcessOprfRequest(byte[] oprfRequest, Guid accountId)
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

        Result<RegistrationRequest, OpaqueRelayFailure> registrationRequestResult =
            RegistrationRequest.Create(oprfRequest);

        if (registrationRequestResult.IsErr)
        {
            throw new InvalidOperationException(
                $"Invalid OPRF request: {registrationRequestResult.UnwrapErr().Message}");
        }

        RegistrationRequest registrationRequest = registrationRequestResult.Unwrap();
        Result<RegistrationResponse, OpaqueRelayFailure> result =
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
                return (ok.Data, keyVersion);
            },
            err => throw new InvalidOperationException($"OPRF processing failed: {err.Message}")
        );
    }

    public Result<(OpaqueSignInInitResponse Response, byte[] RelayMac), OpaqueFailure> InitiateSignIn(
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

        byte[] relayCredentials = ConstructRelayCredentials(registrationRecord);

        Result<KE2, OpaqueRelayFailure> ke2Result =
            keyRingService.GenerateKe2(ke1, queryRecord.AccountId, relayCredentials, queryRecord.OpaqueKeyVersion);

        return ke2Result.Match(
            ok =>
            {
                Span<byte> relayMacSpan = stackalloc byte[RelayMacSize];
                ExtractRelayMac(ok.Data, relayMacSpan);
                byte[] relayMac = relayMacSpan.ToArray();

                if (Log.IsEnabled(LogEventLevel.Debug))
                {
                    Log.Debug(
                        "[OPAQUE-SIGNIN-INIT] accountId={AccountId} ke2Len={Length} ke2={Data} relayMac={RelayMac}",
                        queryRecord.AccountId,
                        ok.Data.Length,
                        Convert.ToHexString(ok.Data),
                        Convert.ToHexString(relayMac));
                }

                OpaqueSignInInitResponse response =
                    BuildSignInInitResponse(ok.Data, registrationRecord);
                return Result<(OpaqueSignInInitResponse, byte[]), OpaqueFailure>.Ok((response, relayMac));
            },
            err => Result<(OpaqueSignInInitResponse, byte[]), OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput($"KE2 generation failed: {err.Message}")));
    }

    public Result<(SodiumSecureMemoryHandle MasterKeyHandle, OpaqueSignInFinalizeResponse Response), OpaqueFailure>
        CompleteSignInWithMasterKey(OpaqueSignInFinalizeRequest request, byte[]? relayMac, int keyVersion)
    {
        if (relayMac is null)
        {
            return Result<(SodiumSecureMemoryHandle, OpaqueSignInFinalizeResponse), OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput("Relay MAC is required for sign-in finalization."));
        }

        Result<KE3, OpaqueFailure> ke3ValidationResult = ValidateKe3(request);
        if (ke3ValidationResult.IsErr)
        {
            return Result<(SodiumSecureMemoryHandle, OpaqueSignInFinalizeResponse), OpaqueFailure>.Err(
                ke3ValidationResult.UnwrapErr());
        }

        KE3 ke3 = ke3ValidationResult.Unwrap();
        if (Log.IsEnabled(LogEventLevel.Debug))
        {
            Log.Debug(
                "[OPAQUE-SIGNIN-FINAL] ke3Len={Length} ke3={Data} relayMacLen={RelayMacLen} relayMac={RelayMac}",
                ke3.Data.Length,
                Convert.ToHexString(ke3.Data),
                relayMac.Length,
                relayMac.Length > 0 ? Convert.ToHexString(relayMac) : string.Empty);
        }

        Result<SodiumSecureMemoryHandle, OpaqueRelayFailure> result =
            keyRingService.FinishAuthenticationWithMasterKey(ke3, keyVersion);

        return result.Match(
            ok => Result<(SodiumSecureMemoryHandle, OpaqueSignInFinalizeResponse), OpaqueFailure>.Ok(
                (ok, BuildSuccessfulFinalizeResponse(relayMac))),
            _ => Result<(SodiumSecureMemoryHandle, OpaqueSignInFinalizeResponse), OpaqueFailure>.Ok(
                (null!, BuildFailedFinalizeResponse()))
        );
    }

    private static Result<KE1, OpaqueFailure> ValidateKe1(OpaqueSignInInitRequest request)
    {
        Result<KE1, OpaqueRelayFailure> ke1Result = KE1.Create(request.PeerOprf.ToByteArray());
        return ke1Result.IsErr
            ? Result<KE1, OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput($"Invalid KE1: {ke1Result.UnwrapErr().Message}"))
            : Result<KE1, OpaqueFailure>.Ok(ke1Result.Unwrap());
    }

    private static Result<KE3, OpaqueFailure> ValidateKe3(OpaqueSignInFinalizeRequest request)
    {
        Result<KE3, OpaqueRelayFailure> ke3Result = KE3.Create(request.ClientMac.ToByteArray());
        return ke3Result.IsErr
            ? Result<KE3, OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput($"Invalid KE3: {ke3Result.UnwrapErr().Message}"))
            : Result<KE3, OpaqueFailure>.Ok(ke3Result.Unwrap());
    }

    private static OpaqueSignInInitResponse BuildSignInInitResponse(byte[] ke2Data, byte[] registrationRecord)
    {
        ReadOnlySpan<byte> ke2Span = ke2Data.AsSpan();

        Span<byte> relayOprfResponseBuffer = stackalloc byte[RelayOprfResponseSize];
        Span<byte> relayEphemeralKeyBuffer = stackalloc byte[RelayEphemeralKeySize];

        ke2Span.Slice(RelayEphemeralKeyOffset, RelayEphemeralKeySize).CopyTo(relayEphemeralKeyBuffer);
        ke2Span.Slice(RelayOprfResponseOffset, RelayOprfResponseSize).CopyTo(relayOprfResponseBuffer);

        return new OpaqueSignInInitResponse
        {
            ServerOprfResponse = ByteString.CopyFrom(relayOprfResponseBuffer),
            ServerEphemeralPublicKey = ByteString.CopyFrom(relayEphemeralKeyBuffer),
            RegistrationRecord = ByteString.CopyFrom(registrationRecord),
            ServerStateToken = ByteString.CopyFrom(ke2Data),
            Result = OpaqueOperationResult.Succeeded
        };
    }

    private static void ExtractRelayMac(ReadOnlySpan<byte> ke2Data, Span<byte> destination)
    {
        ke2Data.Slice(RelayMacOffset, RelayMacSize).CopyTo(destination);
    }

    private static OpaqueSignInFinalizeResponse BuildSuccessfulFinalizeResponse(byte[] relayMac)
    {
        return new OpaqueSignInFinalizeResponse
        {
            ServerMac = ByteString.CopyFrom(relayMac),
            Result = OpaqueOperationResult.Succeeded,
            Message = AuthenticationSuccessful
        };
    }

    private static OpaqueSignInFinalizeResponse BuildFailedFinalizeResponse()
    {
        return new OpaqueSignInFinalizeResponse
        {
            Result = OpaqueOperationResult.InvalidCredentials,
            Message = AuthenticationFailed
        };
    }

    private static byte[] ConstructRelayCredentials(byte[] agentRegistrationRecord)
    {
        ArgumentNullException.ThrowIfNull(agentRegistrationRecord);

        if (agentRegistrationRecord.Length != AgentRegistrationRecordSize)
        {
            throw new ArgumentException(
                $"Agent registration record must be {AgentRegistrationRecordSize} bytes, got {agentRegistrationRecord.Length}");
        }

        byte[] credentials = ArrayPool<byte>.Shared.Rent(RelayCredentialsSize);
        try
        {
            Span<byte> credentialsSpan = credentials.AsSpan(0, RelayCredentialsSize);
            ReadOnlySpan<byte> recordSpan = agentRegistrationRecord.AsSpan();
            recordSpan.CopyTo(credentialsSpan);

            byte[] result = new byte[RelayCredentialsSize];
            credentialsSpan.CopyTo(result);
            return result;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(credentials, clearArray: true);
        }
    }
}
