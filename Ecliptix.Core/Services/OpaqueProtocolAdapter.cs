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
    private const int DummyKeySize = 32;
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
                ok => ok.Response.Data,
                err => throw new InvalidOperationException($"OPRF processing failed: {err.Message}")
            );
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error processing OPRF request");
            throw;
        }
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
            byte[] storedCredentials = queryRecord.RegistrationRecord;

            Task<Result<KE2, OpaqueServerFailure>> ke2Task = nativeService.GenerateKE2Async(ke1, storedCredentials);
            Result<KE2, OpaqueServerFailure> ke2Result = ke2Task.GetAwaiter().GetResult();

            return ke2Result.Match(
                ok =>
                {
                    OpaqueSignInInitResponse response = new OpaqueSignInInitResponse
                    {
                        ServerOprfResponse = ByteString.CopyFrom(ok.Data.Take(ServerOprfResponseSize).ToArray()),
                        ServerEphemeralPublicKey = ByteString.CopyFrom(ok.Data.Skip(ServerOprfResponseSize)
                            .Take(ServerEphemeralKeySize).ToArray()),
                        RegistrationRecord = ByteString.CopyFrom(storedCredentials),
                        ServerStateToken = ByteString.CopyFrom(ok.Data),
                        Result = OpaqueSignInInitResponse.Types.SignInResult.Succeeded
                    };

                    Log.Information("Sign-in initiated successfully, KE2 generated (length: {Length} bytes)",
                        ok.Data.Length);
                    return Result<OpaqueSignInInitResponse, OpaqueFailure>.Ok(response);
                },
                err =>
                {
                    Log.Warning("KE2 generation failed: {Error}", err.Message);
                    return Result<OpaqueSignInInitResponse, OpaqueFailure>.Err(
                        OpaqueFailure.InvalidInput($"KE2 generation failed: {err.Message}"));
                }
            );
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error in InitiateSignIn adapter");
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
                Log.Warning("Invalid KE3 in finalize request: {Error}", ke3Result.UnwrapErr().Message);
                return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Err(
                    OpaqueFailure.InvalidInput($"Invalid KE3: {ke3Result.UnwrapErr().Message}"));
            }

            KE3 ke3 = ke3Result.Unwrap();

            Task<Result<SessionKey, OpaqueServerFailure>> sessionKeyTask = nativeService.FinishAuthenticationAsync(ke3);
            Result<SessionKey, OpaqueServerFailure> sessionKeyResult = sessionKeyTask.GetAwaiter().GetResult();

            return sessionKeyResult.Match(
                ok =>
                {
                    OpaqueSignInFinalizeResponse response = new OpaqueSignInFinalizeResponse
                    {
                        SessionKey = ByteString.CopyFrom(ok.Data),
                        ServerMac = ByteString.Empty,
                        Result = OpaqueSignInFinalizeResponse.Types.SignInResult.Succeeded,
                        Message = AuthenticationSuccessful
                    };

                    Log.Information("Sign-in finalized successfully, session key generated (length: {Length} bytes)",
                        ok.Data.Length);
                    return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Ok(response);
                },
                err =>
                {
                    Log.Warning("Authentication failed during finalization: {Error}", err.Message);
                    OpaqueSignInFinalizeResponse response = new OpaqueSignInFinalizeResponse
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

            byte[] sessionKey = new byte[SessionKeySize];
            RandomNumberGenerator.Fill(sessionKey);

            Log.Information("Registration completed successfully with session key generation (length: {Length} bytes)",
                sessionKey.Length);
            return Result<byte[], OpaqueFailure>.Ok(sessionKey);
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
}