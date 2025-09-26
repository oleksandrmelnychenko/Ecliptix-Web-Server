using System.Security.Cryptography;
using Ecliptix.Domain.Utilities;
using Ecliptix.Domain.Memberships.OPAQUE;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Security.Opaque.Models.AuthenticationMessages;
using Ecliptix.Security.Opaque.Models.RegistrationMessages;
using Ecliptix.Security.Opaque.Services;
using Ecliptix.Security.Opaque.Failures;
using Google.Protobuf;
using Serilog;

namespace Ecliptix.Core.Services;

public sealed class OpaqueProtocolAdapter(INativeOpaqueProtocolService nativeService) : IOpaqueProtocolService
{
    private const int SessionKeySize = 32;
    private const int ContextTokenSize = 64;
    private const int ServerOprfResponseSize = 32;
    private const int ServerEphemeralKeySize = 33;
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
        try
        {
            byte[] oprfRequestArray = oprfRequest.ToArray();
            Result<RegistrationRequest, OpaqueServerFailure> registrationRequestResult =
                RegistrationRequest.Create(oprfRequestArray);

            if (registrationRequestResult.IsErr)
            {
                throw new InvalidOperationException(
                    $"Invalid OPRF request: {registrationRequestResult.UnwrapErr().Message}");
            }

            RegistrationRequest registrationRequest = registrationRequestResult.Unwrap();
            Task<Result<(RegistrationResponse Response, byte[] ServerCredentials), OpaqueServerFailure>> result =
                nativeService.CreateRegistrationResponseAsync(registrationRequest);

            return result.GetAwaiter().GetResult().Match(
                ok => {
                    byte[] maskingKey = new byte[32];
                    Array.Copy(ok.ServerCredentials, 144, maskingKey, 0, 32);
                    return (ok.Response.Data, maskingKey);
                },
                err => throw new InvalidOperationException($"OPRF processing failed: {err.Message}")
            );
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error processing OPRF request");
            throw;
        }
    }

    private static byte[] ConstructServerCredentials(byte[] clientRegistrationRecord, byte[] maskingKey)
    {
        if (clientRegistrationRecord.Length != 176)
            throw new ArgumentException($"Client registration record must be 176 bytes, got {clientRegistrationRecord.Length}");
        if (maskingKey.Length != 32)
            throw new ArgumentException($"Masking key must be 32 bytes, got {maskingKey.Length}");

        byte[] credentials = new byte[208];

        Array.Copy(clientRegistrationRecord, 0, credentials, 0, 144);
        Array.Copy(maskingKey, 0, credentials, 144, 32);
        Array.Copy(clientRegistrationRecord, 144, credentials, 176, 32);

        return credentials;
    }

    public Result<OpaqueSignInInitResponse, OpaqueFailure> InitiateSignIn(
        OpaqueSignInInitRequest request, MembershipOpaqueQueryRecord queryRecord)
    {
        try
        {
            Result<KE1, OpaqueServerFailure> ke1Result = KE1.Create(request.PeerOprf.ToByteArray());
            if (ke1Result.IsErr)
            {
                return Result<OpaqueSignInInitResponse, OpaqueFailure>.Err(
                    OpaqueFailure.InvalidInput($"Invalid KE1: {ke1Result.UnwrapErr().Message}"));
            }

            KE1 ke1 = ke1Result.Unwrap();

            byte[] serverCredentials = ConstructServerCredentials(queryRecord.RegistrationRecord, queryRecord.MaskingKey);

            Task<Result<KE2, OpaqueServerFailure>> ke2Task = nativeService.GenerateKE2Async(ke1, serverCredentials);
            Result<KE2, OpaqueServerFailure> ke2Result = ke2Task.GetAwaiter().GetResult();

            return ke2Result.Match(
                ok =>
                {
                    OpaqueSignInInitResponse response = new()
                    {
                        ServerOprfResponse = ByteString.CopyFrom(ok.Data.Take(ServerOprfResponseSize).ToArray()),
                        ServerEphemeralPublicKey = ByteString.CopyFrom(ok.Data.Skip(ServerOprfResponseSize)
                            .Take(ServerEphemeralKeySize).ToArray()),
                        RegistrationRecord = ByteString.CopyFrom(queryRecord.RegistrationRecord),
                        ServerStateToken = ByteString.CopyFrom(ok.Data),
                        Result = OpaqueSignInInitResponse.Types.SignInResult.Succeeded
                    };

                    return Result<OpaqueSignInInitResponse, OpaqueFailure>.Ok(response);
                },
                err =>
                {
                    return Result<OpaqueSignInInitResponse, OpaqueFailure>.Err(
                        OpaqueFailure.InvalidInput($"KE2 generation failed: {err.Message}"));
                }
            );
        }
        catch (Exception ex)
        {
            return Result<OpaqueSignInInitResponse, OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput($"Sign-in initiation failed: {ex.Message}"));
        }
    }

    public Result<OpaqueSignInFinalizeResponse, OpaqueFailure> FinalizeSignIn(OpaqueSignInFinalizeRequest request)
    {
        try
        {
            Result<KE3, OpaqueServerFailure> ke3Result = KE3.Create(request.ClientMac.ToByteArray());
            if (ke3Result.IsErr)
            {
                return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Err(
                    OpaqueFailure.InvalidInput($"Invalid KE3: {ke3Result.UnwrapErr().Message}"));
            }

            KE3 ke3 = ke3Result.Unwrap();

            Task<Result<SessionKey, OpaqueServerFailure>> sessionKeyTask = nativeService.FinishAuthenticationAsync(ke3);
            Result<SessionKey, OpaqueServerFailure> sessionKeyResult = sessionKeyTask.GetAwaiter().GetResult();

            return sessionKeyResult.Match(
                ok =>
                {
                    OpaqueSignInFinalizeResponse response = new()
                    {
                        SessionKey = ByteString.CopyFrom(ok.Data),
                        ServerMac = ByteString.Empty,
                        Result = OpaqueSignInFinalizeResponse.Types.SignInResult.Succeeded,
                        Message = AuthenticationSuccessful
                    };

                    return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Ok(response);
                },
                err =>
                {
                    OpaqueSignInFinalizeResponse response = new()
                    {
                        Result = OpaqueSignInFinalizeResponse.Types.SignInResult.InvalidCredentials,
                        Message = AuthenticationFailed
                    };

                    return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Ok(response);
                }
            );
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error in FinalizeSignIn adapter");
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
            if (peerRegistrationRecord == null || peerRegistrationRecord.Length == 0)
            {
                return Result<byte[], OpaqueFailure>.Err(
                    OpaqueFailure.InvalidInput(RegistrationRecordEmptyError));
            }

            // IMPORTANT: Registration does NOT generate session keys!
            // Session keys are only created during authentication through the OPAQUE protocol.
            // This method should not return a session key, but is kept for compatibility.

            Log.Information("Registration completed successfully. Client record length: {Length} bytes. " +
                          "Note: Session keys are derived during authentication, not registration.",
                          peerRegistrationRecord.Length);

            // Return empty array to indicate no session key from registration
            return Result<byte[], OpaqueFailure>.Ok(Array.Empty<byte>());
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error in CompleteRegistrationWithSessionKey adapter");
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
        try
        {
            Result<KE3, OpaqueServerFailure> ke3Result = KE3.Create(request.ClientMac.ToByteArray());
            if (ke3Result.IsErr)
            {
                return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Err(
                    OpaqueFailure.InvalidInput($"Invalid KE3: {ke3Result.UnwrapErr().Message}"));
            }

            KE3 ke3 = ke3Result.Unwrap();

            Task<Result<SessionKey, OpaqueServerFailure>> sessionKeyTask = nativeService.FinishAuthenticationAsync(ke3);
            Result<SessionKey, OpaqueServerFailure> sessionKeyResult = sessionKeyTask.GetAwaiter().GetResult();

            return sessionKeyResult.Match(
                ok =>
                {
                    OpaqueSignInFinalizeResponse response = new()
                    {
                        SessionKey = ByteString.CopyFrom(ok.Data),
                        ServerMac = ByteString.CopyFrom(serverMac),
                        Result = OpaqueSignInFinalizeResponse.Types.SignInResult.Succeeded,
                        Message = AuthenticationSuccessful
                    };

                    Log.Information("Sign-in finalized successfully with server MAC, session key generated (length: {Length} bytes), server MAC included (length: {MacLength} bytes)",
                        ok.Data.Length, serverMac.Length);
                    return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Ok(response);
                },
                err =>
                {
                    Log.Warning("Authentication failed during finalization: {Error}", err.Message);
                    OpaqueSignInFinalizeResponse response = new()
                    {
                        Result = OpaqueSignInFinalizeResponse.Types.SignInResult.InvalidCredentials,
                        Message = AuthenticationFailed
                    };

                    return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Ok(response);
                }
            );
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error in FinalizeSignIn with server MAC adapter");
            return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput($"Sign-in finalization with server MAC failed: {ex.Message}"));
        }
    }

    public Result<(OpaqueSignInInitResponse Response, byte[] ServerMac), OpaqueFailure> InitiateSignInWithServerMac(
        OpaqueSignInInitRequest request, MembershipOpaqueQueryRecord queryRecord)
    {
        try
        {
            Result<KE1, OpaqueServerFailure> ke1Result = KE1.Create(request.PeerOprf.ToByteArray());
            if (ke1Result.IsErr)
            {
                return Result<(OpaqueSignInInitResponse, byte[]), OpaqueFailure>.Err(
                    OpaqueFailure.InvalidInput($"Invalid KE1: {ke1Result.UnwrapErr().Message}"));
            }

            KE1 ke1 = ke1Result.Unwrap();

            byte[] serverCredentials = ConstructServerCredentials(queryRecord.RegistrationRecord, queryRecord.MaskingKey);

            Task<Result<KE2, OpaqueServerFailure>> ke2Task = nativeService.GenerateKE2Async(ke1, serverCredentials);
            Result<KE2, OpaqueServerFailure> ke2Result = ke2Task.GetAwaiter().GetResult();

            return ke2Result.Match(
                ok =>
                {
                    // Extract Server MAC from KE2 data (bytes 240-303, total 64 bytes)
                    byte[] serverMac = ok.Data.Skip(240).Take(64).ToArray();

                    OpaqueSignInInitResponse response = new()
                    {
                        ServerOprfResponse = ByteString.CopyFrom(ok.Data.Take(ServerOprfResponseSize).ToArray()),
                        ServerEphemeralPublicKey = ByteString.CopyFrom(ok.Data.Skip(ServerOprfResponseSize)
                            .Take(ServerEphemeralKeySize).ToArray()),
                        RegistrationRecord = ByteString.CopyFrom(queryRecord.RegistrationRecord),
                        ServerStateToken = ByteString.CopyFrom(ok.Data),
                        Result = OpaqueSignInInitResponse.Types.SignInResult.Succeeded
                    };

                    Log.Information("Sign-in initiated with server MAC, KE2 generated (length: {Length} bytes), Server MAC extracted (length: {MacLength} bytes)",
                        ok.Data.Length, serverMac.Length);
                    return Result<(OpaqueSignInInitResponse, byte[]), OpaqueFailure>.Ok((response, serverMac));
                },
                err =>
                {
                    return Result<(OpaqueSignInInitResponse, byte[]), OpaqueFailure>.Err(
                        OpaqueFailure.InvalidInput($"KE2 generation failed: {err.Message}"));
                }
            );
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error in InitiateSignInWithServerMac adapter");
            return Result<(OpaqueSignInInitResponse, byte[]), OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput($"Sign-in initiation with server MAC failed: {ex.Message}"));
        }
    }
}