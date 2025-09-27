using System.Security.Cryptography;
using Ecliptix.Utilities;
using Ecliptix.Security.Opaque.Models;
using Ecliptix.Security.Opaque.Contracts;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Security.Opaque.Models.AuthenticationMessages;
using Ecliptix.Security.Opaque.Models.RegistrationMessages;
using Ecliptix.Security.Opaque.Failures;
using Google.Protobuf;

namespace Ecliptix.Security.Opaque.Services;

public sealed class OpaqueProtocolAdapter(INativeOpaqueProtocolService nativeService) : IOpaqueProtocolService
{
    private const int SessionKeySize = 32;
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
    private const string RegistrationRecordEmptyError = "Registration record cannot be empty";

    public byte[] ProcessOprfRequest(byte[] oprfRequest)
    {
        return ProcessOprfRequest(oprfRequest.AsSpan());
    }

    public byte[] ProcessOprfRequest(ReadOnlySpan<byte> oprfRequest)
    {
        (byte[] response, _) = ProcessOprfRequestWithMaskingKey(oprfRequest);
        return response;
    }

    public (byte[] Response, byte[] MaskingKey) ProcessOprfRequestWithMaskingKey(byte[] oprfRequest)
    {
        return ProcessOprfRequestWithMaskingKey(oprfRequest.AsSpan());
    }

    public (byte[] Response, byte[] MaskingKey) ProcessOprfRequestWithMaskingKey(ReadOnlySpan<byte> oprfRequest)
    {
        return ProcessOprfRequestWithMaskingKeyAsync(oprfRequest.ToArray()).GetAwaiter().GetResult();
    }

    private async Task<(byte[] Response, byte[] MaskingKey)> ProcessOprfRequestWithMaskingKeyAsync(byte[] oprfRequest)
    {
        try
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
                await nativeService.CreateRegistrationResponseAsync(registrationRequest).ConfigureAwait(false);

            return result.Match(
                ok => {
                    byte[] maskingKey = ok.ServerCredentials.AsSpan(CredentialsMaskingKeyOffset, MaskingKeySize).ToArray();
                    return (ok.Response.Data, maskingKey);
                },
                err => throw new InvalidOperationException($"OPRF processing failed: {err.Message}")
            );
        }
        catch (Exception ex)
        {
            throw;
        }
    }

    private static Result<Unit, OpaqueFailure> ValidateSignInInitRequest(OpaqueSignInInitRequest request)
    {
        if (request is null)
            return Result<Unit, OpaqueFailure>.Err(OpaqueFailure.InvalidInput("Sign-in init request cannot be null"));

        if (request.PeerOprf is null || request.PeerOprf.IsEmpty)
            return Result<Unit, OpaqueFailure>.Err(OpaqueFailure.InvalidInput("Peer OPRF data cannot be null or empty"));

        return Result<Unit, OpaqueFailure>.Ok(Unit.Value);
    }

    private static Result<Unit, OpaqueFailure> ValidateSignInFinalizeRequest(OpaqueSignInFinalizeRequest request)
    {
        if (request is null)
            return Result<Unit, OpaqueFailure>.Err(OpaqueFailure.InvalidInput("Sign-in finalize request cannot be null"));

        if (request.ClientMac is null || request.ClientMac.IsEmpty)
            return Result<Unit, OpaqueFailure>.Err(OpaqueFailure.InvalidInput("Client MAC cannot be null or empty"));

        return Result<Unit, OpaqueFailure>.Ok(Unit.Value);
    }

    private static Result<Unit, OpaqueFailure> ValidateQueryRecord(MembershipOpaqueQueryRecord queryRecord)
    {
        if (queryRecord is null)
            return Result<Unit, OpaqueFailure>.Err(OpaqueFailure.InvalidInput("Query record cannot be null"));

        if (queryRecord.RegistrationRecord is null || queryRecord.RegistrationRecord.Length != ClientRegistrationRecordSize)
            return Result<Unit, OpaqueFailure>.Err(OpaqueFailure.InvalidInput(
                $"Registration record must be exactly {ClientRegistrationRecordSize} bytes"));

        if (queryRecord.MaskingKey is null || queryRecord.MaskingKey.Length != MaskingKeySize)
            return Result<Unit, OpaqueFailure>.Err(OpaqueFailure.InvalidInput(
                $"Masking key must be exactly {MaskingKeySize} bytes"));

        return Result<Unit, OpaqueFailure>.Ok(Unit.Value);
    }

    private static Result<KE1, OpaqueFailure> ValidateKE1(OpaqueSignInInitRequest request)
    {
        var requestValidation = ValidateSignInInitRequest(request);
        if (requestValidation.IsErr)
            return Result<KE1, OpaqueFailure>.Err(requestValidation.UnwrapErr());

        Result<KE1, OpaqueServerFailure> ke1Result = KE1.Create(request.PeerOprf.ToByteArray());
        return ke1Result.IsErr
            ? Result<KE1, OpaqueFailure>.Err(OpaqueFailure.InvalidInput($"Invalid KE1: {ke1Result.UnwrapErr().Message}"))
            : Result<KE1, OpaqueFailure>.Ok(ke1Result.Unwrap());
    }

    private static Result<KE3, OpaqueFailure> ValidateKE3(OpaqueSignInFinalizeRequest request)
    {
        var requestValidation = ValidateSignInFinalizeRequest(request);
        if (requestValidation.IsErr)
            return Result<KE3, OpaqueFailure>.Err(requestValidation.UnwrapErr());

        Result<KE3, OpaqueServerFailure> ke3Result = KE3.Create(request.ClientMac.ToByteArray());
        return ke3Result.IsErr
            ? Result<KE3, OpaqueFailure>.Err(OpaqueFailure.InvalidInput($"Invalid KE3: {ke3Result.UnwrapErr().Message}"))
            : Result<KE3, OpaqueFailure>.Ok(ke3Result.Unwrap());
    }

    private static OpaqueSignInInitResponse BuildSignInInitResponse(byte[] ke2Data, byte[] registrationRecord)
    {
        ReadOnlySpan<byte> ke2Span = ke2Data.AsSpan();

        return new OpaqueSignInInitResponse
        {
            ServerOprfResponse = ByteString.CopyFrom(ke2Span.Slice(0, ServerOprfResponseSize)),
            ServerEphemeralPublicKey = ByteString.CopyFrom(ke2Span.Slice(ServerOprfResponseSize, ServerEphemeralKeySize)),
            RegistrationRecord = ByteString.CopyFrom(registrationRecord),
            ServerStateToken = ByteString.CopyFrom(ke2Data),
            Result = OpaqueSignInInitResponse.Types.SignInResult.Succeeded
        };
    }

    private static byte[] ExtractServerMac(byte[] ke2Data)
    {
        return ke2Data.AsSpan(ServerMacOffset, ServerMacSize).ToArray();
    }

    private static OpaqueSignInFinalizeResponse BuildSuccessfulFinalizeResponse(byte[] sessionKey, byte[]? serverMac)
    {
        return new OpaqueSignInFinalizeResponse
        {
            SessionKey = ByteString.CopyFrom(sessionKey),
            ServerMac = serverMac is not null ? ByteString.CopyFrom(serverMac) : ByteString.Empty,
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
            throw new ArgumentException($"Client registration record must be {ClientRegistrationRecordSize} bytes, got {clientRegistrationRecord.Length}");
        if (maskingKey.Length != MaskingKeySize)
            throw new ArgumentException($"Masking key must be {MaskingKeySize} bytes, got {maskingKey.Length}");

        byte[] credentials = new byte[ServerCredentialsSize];
        Span<byte> credentialsSpan = credentials.AsSpan();
        ReadOnlySpan<byte> recordSpan = clientRegistrationRecord.AsSpan();
        ReadOnlySpan<byte> maskingKeySpan = maskingKey.AsSpan();

        recordSpan.Slice(0, CredentialsBaseOffset).CopyTo(credentialsSpan.Slice(0, CredentialsBaseOffset));
        maskingKeySpan.CopyTo(credentialsSpan.Slice(CredentialsMaskingKeyOffset, MaskingKeySize));
        recordSpan.Slice(CredentialsBaseOffset, MaskingKeySize).CopyTo(
            credentialsSpan.Slice(CredentialsExportKeyOffset, MaskingKeySize));

        return credentials;
    }

    public Result<OpaqueSignInInitResponse, OpaqueFailure> InitiateSignIn(
        OpaqueSignInInitRequest request, MembershipOpaqueQueryRecord queryRecord)
    {
        return InitiateSignInAsync(request, queryRecord).GetAwaiter().GetResult();
    }

    private async Task<Result<OpaqueSignInInitResponse, OpaqueFailure>> InitiateSignInAsync(
        OpaqueSignInInitRequest request, MembershipOpaqueQueryRecord queryRecord)
    {
        try
        {
            var queryValidation = ValidateQueryRecord(queryRecord);
            if (queryValidation.IsErr)
                return Result<OpaqueSignInInitResponse, OpaqueFailure>.Err(queryValidation.UnwrapErr());

            var ke1ValidationResult = ValidateKE1(request);
            if (ke1ValidationResult.IsErr)
                return Result<OpaqueSignInInitResponse, OpaqueFailure>.Err(ke1ValidationResult.UnwrapErr());

            KE1 ke1 = ke1ValidationResult.Unwrap();
            byte[] serverCredentials = ConstructServerCredentials(queryRecord.RegistrationRecord, queryRecord.MaskingKey);

            Result<KE2, OpaqueServerFailure> ke2Result =
                await nativeService.GenerateKE2Async(ke1, serverCredentials).ConfigureAwait(false);

            return ke2Result.Match(
                ok => Result<OpaqueSignInInitResponse, OpaqueFailure>.Ok(
                    BuildSignInInitResponse(ok.Data, queryRecord.RegistrationRecord)),
                err => Result<OpaqueSignInInitResponse, OpaqueFailure>.Err(
                    OpaqueFailure.InvalidInput($"KE2 generation failed: {err.Message}")));
        }
        catch (Exception ex)
        {
            return Result<OpaqueSignInInitResponse, OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput($"Sign-in initiation failed: {ex.Message}"));
        }
    }

    public Result<OpaqueSignInFinalizeResponse, OpaqueFailure> FinalizeSignIn(OpaqueSignInFinalizeRequest request)
    {
        return FinalizeSignInAsync(request, null).GetAwaiter().GetResult();
    }

    private async Task<Result<OpaqueSignInFinalizeResponse, OpaqueFailure>> FinalizeSignInAsync(
        OpaqueSignInFinalizeRequest request, byte[]? serverMac)
    {
        try
        {
            var ke3ValidationResult = ValidateKE3(request);
            if (ke3ValidationResult.IsErr)
                return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Err(ke3ValidationResult.UnwrapErr());

            KE3 ke3 = ke3ValidationResult.Unwrap();

            Result<SessionKey, OpaqueServerFailure> sessionKeyResult =
                await nativeService.FinishAuthenticationAsync(ke3).ConfigureAwait(false);

            return sessionKeyResult.Match(
                ok => Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Ok(
                    BuildSuccessfulFinalizeResponse(ok.Data, serverMac)),
                err => Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Ok(
                    BuildFailedFinalizeResponse())
            );
        }
        catch (Exception ex)
        {
            return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput($"Sign-in finalization failed: {ex.Message}"));
        }
    }

    public Result<Unit, OpaqueFailure> CompleteRegistration(byte[] peerRegistrationRecord)
    {
        Result<byte[], OpaqueFailure> result = CompleteRegistrationWithSessionKey(peerRegistrationRecord);
        return result.Match(
            ok => Result<Unit, OpaqueFailure>.Ok(Unit.Value),
            err => Result<Unit, OpaqueFailure>.Err(err)
        );
    }

    public Result<byte[], OpaqueFailure> CompleteRegistrationWithSessionKey(byte[] peerRegistrationRecord)
    {
        try
        {
            if (peerRegistrationRecord is null || peerRegistrationRecord.Length == 0)
            {
                return Result<byte[], OpaqueFailure>.Err(
                    OpaqueFailure.InvalidInput(RegistrationRecordEmptyError));
            }


            return Result<byte[], OpaqueFailure>.Ok(Array.Empty<byte>());
        }
        catch (Exception ex)
        {
            return Result<byte[], OpaqueFailure>.Err(
                OpaqueFailure.CalculateRegistrationRecord($"Registration completion failed: {ex.Message}"));
        }
    }

    public Result<AuthContextTokenResponse, OpaqueFailure> GenerateAuthenticationContext(
        Guid membershipId, Guid mobileNumberId)
    {
        try
        {
            byte[] contextToken = new byte[ContextTokenSize];
            RandomNumberGenerator.Fill(contextToken);

            DateTime expiresAt = DateTime.UtcNow.AddHours(AuthTokenExpirationHours);

            AuthContextTokenResponse response = new()
            {
                ContextToken = contextToken,
                MembershipId = membershipId,
                MobileNumberId = mobileNumberId,
                ExpiresAt = expiresAt
            };

            return Result<AuthContextTokenResponse, OpaqueFailure>.Ok(response);
        }
        catch (Exception ex)
        {
            return Result<AuthContextTokenResponse, OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput($"Authentication context generation failed: {ex.Message}"));
        }
    }

    public Result<OpaqueSignInFinalizeResponse, OpaqueFailure> FinalizeSignIn(OpaqueSignInFinalizeRequest request, byte[] serverMac)
    {
        return FinalizeSignInAsync(request, serverMac).GetAwaiter().GetResult();
    }

    public Result<(OpaqueSignInInitResponse Response, byte[] ServerMac), OpaqueFailure> InitiateSignInWithServerMac(
        OpaqueSignInInitRequest request, MembershipOpaqueQueryRecord queryRecord)
    {
        return InitiateSignInWithServerMacAsync(request, queryRecord).GetAwaiter().GetResult();
    }

    private async Task<Result<(OpaqueSignInInitResponse Response, byte[] ServerMac), OpaqueFailure>> InitiateSignInWithServerMacAsync(
        OpaqueSignInInitRequest request, MembershipOpaqueQueryRecord queryRecord)
    {
        try
        {
            var queryValidation = ValidateQueryRecord(queryRecord);
            if (queryValidation.IsErr)
                return Result<(OpaqueSignInInitResponse, byte[]), OpaqueFailure>.Err(queryValidation.UnwrapErr());

            var ke1ValidationResult = ValidateKE1(request);
            if (ke1ValidationResult.IsErr)
                return Result<(OpaqueSignInInitResponse, byte[]), OpaqueFailure>.Err(ke1ValidationResult.UnwrapErr());

            KE1 ke1 = ke1ValidationResult.Unwrap();
            byte[] serverCredentials = ConstructServerCredentials(queryRecord.RegistrationRecord, queryRecord.MaskingKey);

            Result<KE2, OpaqueServerFailure> ke2Result =
                await nativeService.GenerateKE2Async(ke1, serverCredentials).ConfigureAwait(false);

            return ke2Result.Match(
                ok =>
                {
                    byte[] serverMac = ExtractServerMac(ok.Data);
                    OpaqueSignInInitResponse response = BuildSignInInitResponse(ok.Data, queryRecord.RegistrationRecord);
                    return Result<(OpaqueSignInInitResponse, byte[]), OpaqueFailure>.Ok((response, serverMac));
                },
                err => Result<(OpaqueSignInInitResponse, byte[]), OpaqueFailure>.Err(
                    OpaqueFailure.InvalidInput($"KE2 generation failed: {err.Message}"))
            );
        }
        catch (Exception ex)
        {
            return Result<(OpaqueSignInInitResponse, byte[]), OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput($"Sign-in initiation with server MAC failed: {ex.Message}"));
        }
    }
}