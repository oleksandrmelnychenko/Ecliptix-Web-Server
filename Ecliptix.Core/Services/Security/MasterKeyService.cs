using System.Security.Cryptography;
using Akka.Actor;
using Ecliptix.Core;
using Ecliptix.Core.Domain.Protocol;
using Ecliptix.Core.Services.KeyDerivation;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Persistors.CompiledQueries;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.QueryResults;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Domain.Services.Security;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Failures;
using Ecliptix.Utilities.Failures.Sodium;
using Google.Protobuf;
using Microsoft.EntityFrameworkCore;
using Serilog;

namespace Ecliptix.Core.Services.Security;

public class MasterKeyService(
    IHardenedKeyDerivation hardenedKeyDerivation,
    ISecretSharingService secretSharingService,
    IEcliptixActorRegistry actorRegistry,
    IIdentityKeyDerivationService identityKeyDerivationService,
    IDbContextFactory<EcliptixSchemaContext> dbContextFactory)
    : IMasterKeyService
{
    private const int Argon2MemorySize = 262144;
    private const int Argon2Iterations = 4;
    private const int Argon2DegreeOfParallelism = 4;
    private const int EnhancedKeyOutputLength = 64;
    private const int DefaultThreshold = 3;
    private const int DefaultTotalShares = 5;
    private const int MasterKeySize = 32;
    private const int AskTimeoutSeconds = 30;

    private const string KeyDerivationContext = "ecliptix-signin-session";
    private const string RootKeyInfo = "ecliptix-protocol-root-key";

    private const string LogTagServerMasterKeyDerive = "[SERVER-MASTERKEY-DERIVE]";
    private const string LogTagServerMasterKeyRootKey = "[SERVER-MASTERKEY-ROOTKEY]";
    private const string LogTagServerRootKeyDerive = "[SERVER-ROOTKEY-DERIVE]";
    private const string LogMessageMasterKeyDerived = "Master key derived from OPAQUE session key. MembershipId: {MembershipId}, MasterKeyFingerprint: {MasterKeyFingerprint}";
    private const string LogMessageUsingMasterKeyForRootKey = "Using master key to derive root key. MembershipId: {MembershipId}, MasterKeyFingerprint: {MasterKeyFingerprint}";
    private const string LogMessageRootKeyDerived = "Root key derived from master key using HKDF. MembershipId: {MembershipId}, RootKeyHash: {RootKeyHash}";

    private const string ErrorMessageMasterKeyDerivationFailed = "Master key derivation failed";
    private const string ErrorMessageUnexpectedDerivationError = "Unexpected error during master key derivation";
    private const string ErrorMessageInsufficientShares = "Insufficient shares: found {0}, need at least 3";
    private const string ErrorMessageMetadataDeserializationFailed = "Failed to deserialize share metadata";
    private const string ErrorMessageUnexpectedReconstructionError = "Unexpected error during master key reconstruction";
    private const string ErrorMessagePersistSharesTimeout = "Timeout while persisting shares";
    private const string ErrorMessagePersistSharesFailed = "Failed to persist shares";
    private const string ErrorMessageRetrieveSharesTimeout = "Timeout while retrieving shares";
    private const string ErrorMessageRetrieveSharesFailed = "Failed to retrieve shares";
    private const string ErrorMessageMasterKeyReadFailed = "Failed to read master key bytes";
    private const string ErrorMessageUnexpectedIdentityKeyDerivationError = "Unexpected error during identity key derivation";
    private const string ErrorMessageSharesCheckFailed = "Unexpected error checking shares";
    public async Task<Result<dynamic, FailureBase>> DeriveMasterKeyAndSplitAsync(
        dynamic sessionKeyHandle,
        Guid membershipId)
    {
        SodiumSecureMemoryHandle? enhancedMasterKeyHandle = null;
        SodiumSecureMemoryHandle? masterKeyHandle = null;
        SodiumSecureMemoryHandle? hmacKeyHandle = null;

        try
        {
            KeyDerivationOptions options = new()
            {
                MemorySize = Argon2MemorySize,
                Iterations = Argon2Iterations,
                DegreeOfParallelism = Argon2DegreeOfParallelism,
                UseHardwareEntropy = false,
                OutputLength = EnhancedKeyOutputLength
            };

            Result<SodiumSecureMemoryHandle, KeySplittingFailure> enhancedResult =
                await hardenedKeyDerivation.DeriveEnhancedMasterKeyHandleAsync(
                    sessionKeyHandle,
                    KeyDerivationContext,
                    options);

            if (enhancedResult.IsErr)
            {
                KeySplittingFailure error = enhancedResult.UnwrapErr();
                return Result<dynamic, FailureBase>.Err(error);
            }

            enhancedMasterKeyHandle = enhancedResult.Unwrap();

            ByteString membershipIdentifier = Helpers.GuidToByteString(membershipId);
            Result<SodiumSecureMemoryHandle, SodiumFailure> masterKeyResult =
                MasterKeyDerivation.DeriveMasterKeyHandle(enhancedMasterKeyHandle, membershipIdentifier);

            if (masterKeyResult.IsErr)
            {
                SodiumFailure sodiumError = masterKeyResult.UnwrapErr();
                return Result<dynamic, FailureBase>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"{ErrorMessageMasterKeyDerivationFailed}: {sodiumError.Message}"));
            }

            masterKeyHandle = masterKeyResult.Unwrap();

            Result<byte[], SodiumFailure> masterKeyBytesResult = masterKeyHandle.ReadBytes(masterKeyHandle.Length);
            if (masterKeyBytesResult.IsOk)
            {
                byte[] masterKeyBytes = masterKeyBytesResult.Unwrap();
                string masterKeyFingerprint = CryptoHelpers.ComputeSha256Fingerprint(masterKeyBytes);
                Log.Information($"{LogTagServerMasterKeyDerive} {LogMessageMasterKeyDerived}",
                    membershipId, masterKeyFingerprint);
                CryptographicOperations.ZeroMemory(masterKeyBytes);
            }

            Result<KeySplitResult, KeySplittingFailure> splitResult = await secretSharingService.SplitKeyAsync(
                masterKeyHandle,
                threshold: DefaultThreshold,
                totalShares: DefaultTotalShares,
                hmacKeyHandle: null);

            if (splitResult.IsErr)
            {
                KeySplittingFailure error = splitResult.UnwrapErr();
                return Result<dynamic, FailureBase>.Err(error);
            }

            KeySplitResult keySplitResult = splitResult.Unwrap();

            Result<InsertMasterKeySharesResult, KeySplittingFailure> persistResult =
                await PersistSharesAsync(membershipId, keySplitResult);

            if (persistResult.IsErr)
            {
                KeySplittingFailure error = persistResult.UnwrapErr();
                return Result<dynamic, FailureBase>.Err(error);
            }

            return Result<dynamic, FailureBase>.Ok(keySplitResult);
        }
        catch (Exception ex)
        {
            return Result<dynamic, FailureBase>.Err(
                KeySplittingFailure.KeyDerivationFailed(ErrorMessageUnexpectedDerivationError, ex));
        }
        finally
        {
            enhancedMasterKeyHandle?.Dispose();
            masterKeyHandle?.Dispose();
            hmacKeyHandle?.Dispose();
        }
    }

    public async Task<Result<dynamic, FailureBase>> ReconstructMasterKeyAsync(Guid membershipId)
    {
        try
        {
            Result<MasterKeyShareQueryRecord[], KeySplittingFailure> sharesResult =
                await RetrieveSharesAsync(membershipId);

            if (sharesResult.IsErr)
            {
                KeySplittingFailure error = sharesResult.UnwrapErr();
                return Result<dynamic, FailureBase>.Err(error);
            }

            MasterKeyShareQueryRecord[] shareRecords = sharesResult.Unwrap();

            if (shareRecords.Length < DefaultThreshold)
            {
                return Result<dynamic, FailureBase>.Err(
                    KeySplittingFailure.KeyReconstructionFailed(string.Format(ErrorMessageInsufficientShares, shareRecords.Length)));
            }

            List<KeyShare> shares = [];
            foreach (MasterKeyShareQueryRecord record in shareRecords)
            {
                ShareMetadata? metadata = System.Text.Json.JsonSerializer.Deserialize<ShareMetadata>(record.ShareMetadata);
                if (metadata == null)
                {
                    return Result<dynamic, FailureBase>.Err(
                        KeySplittingFailure.KeyReconstructionFailed(ErrorMessageMetadataDeserializationFailed));
                }

                KeyShare share = new KeyShare(
                    shareData: record.EncryptedShare,
                    index: record.ShareIndex,
                    location: Enum.Parse<ShareLocation>(record.StorageLocation),
                    sessionId: metadata.SessionId
                );

                shares.Add(share);
            }

            Result<SodiumSecureMemoryHandle, KeySplittingFailure> reconstructResult =
                await secretSharingService.ReconstructKeyHandleAsync(shares.ToArray(), hmacKeyHandle: null);

            if (reconstructResult.IsErr)
            {
                KeySplittingFailure error = reconstructResult.UnwrapErr();
                return Result<dynamic, FailureBase>.Err(error);
            }

            SodiumSecureMemoryHandle masterKeyHandle = reconstructResult.Unwrap();

            return Result<dynamic, FailureBase>.Ok(masterKeyHandle);
        }
        catch (Exception ex)
        {
            return Result<dynamic, FailureBase>.Err(
                KeySplittingFailure.KeyReconstructionFailed(ErrorMessageUnexpectedReconstructionError, ex));
        }
    }

    private async Task<Result<InsertMasterKeySharesResult, KeySplittingFailure>> PersistSharesAsync(
        Guid membershipId, KeySplitResult keySplitResult)
    {
        try
        {
            IActorRef masterKeySharePersistor = actorRegistry.Get(ActorIds.MasterKeySharePersistorActor);
            List<ShareData> shareDataList = [];

            foreach (KeyShare share in keySplitResult.Shares)
            {
                string metadata = System.Text.Json.JsonSerializer.Serialize(new
                {
                    ShareId = Convert.ToBase64String(share.ShareId),
                    SessionId = share.SessionId,
                    CreatedAt = share.CreatedAt,
                    HasHmac = share.Hmac != null
                });

                shareDataList.Add(new ShareData(
                    share.ShareIndex,
                    share.ShareData,
                    metadata,
                    share.Location.ToString()
                ));
            }

            InsertMasterKeySharesEvent insertEvent = new(
                membershipId,
                shareDataList
            );

            Result<InsertMasterKeySharesResult, KeySplittingFailure> result =
                await masterKeySharePersistor.Ask<Result<InsertMasterKeySharesResult, KeySplittingFailure>>(
                    insertEvent,
                    TimeSpan.FromSeconds(AskTimeoutSeconds));

            return result;
        }
        catch (TimeoutException)
        {
            return Result<InsertMasterKeySharesResult, KeySplittingFailure>.Err(
                KeySplittingFailure.KeySplittingFailed(ErrorMessagePersistSharesTimeout));
        }
        catch (Exception ex)
        {
            return Result<InsertMasterKeySharesResult, KeySplittingFailure>.Err(
                KeySplittingFailure.KeySplittingFailed($"{ErrorMessagePersistSharesFailed}: {ex.Message}", ex));
        }
    }

    private async Task<Result<MasterKeyShareQueryRecord[], KeySplittingFailure>> RetrieveSharesAsync(Guid membershipId)
    {
        try
        {
            IActorRef masterKeySharePersistor = actorRegistry.Get(ActorIds.MasterKeySharePersistorActor);
            GetMasterKeySharesEvent getEvent = new GetMasterKeySharesEvent(membershipId);

            Result<MasterKeyShareQueryRecord[], KeySplittingFailure> result =
                await masterKeySharePersistor.Ask<Result<MasterKeyShareQueryRecord[], KeySplittingFailure>>(
                    getEvent,
                    TimeSpan.FromSeconds(AskTimeoutSeconds));

            return result;
        }
        catch (TimeoutException)
        {
            return Result<MasterKeyShareQueryRecord[], KeySplittingFailure>.Err(
                KeySplittingFailure.KeyReconstructionFailed(ErrorMessageRetrieveSharesTimeout));
        }
        catch (Exception ex)
        {
            return Result<MasterKeyShareQueryRecord[], KeySplittingFailure>.Err(
                KeySplittingFailure.KeyReconstructionFailed($"{ErrorMessageRetrieveSharesFailed}: {ex.Message}", ex));
        }
    }

    public async Task<Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase>> DeriveIdentityKeysAsync(Guid membershipId)
    {
        SodiumSecureMemoryHandle? masterKeyHandle = null;
        byte[]? rootKeyBytes = null;
        try
        {
            Result<dynamic, FailureBase> reconstructResult = await ReconstructMasterKeyAsync(membershipId);
            if (reconstructResult.IsErr)
            {
                FailureBase error = reconstructResult.UnwrapErr();
                return Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase>.Err(error);
            }

            masterKeyHandle = (SodiumSecureMemoryHandle)reconstructResult.Unwrap();

            Result<byte[], SodiumFailure> masterKeyReadResult = masterKeyHandle.ReadBytes(MasterKeySize);
            if (masterKeyReadResult.IsErr)
            {
                SodiumFailure error = masterKeyReadResult.UnwrapErr();
                return Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"{ErrorMessageMasterKeyReadFailed}: {error.Message}"));
            }

            byte[] masterKeyBytes = masterKeyReadResult.Unwrap();
            try
            {
                string masterKeyFingerprint = CryptoHelpers.ComputeSha256Fingerprint(masterKeyBytes);
                Log.Information($"{LogTagServerMasterKeyRootKey} {LogMessageUsingMasterKeyForRootKey}",
                    membershipId, masterKeyFingerprint);

                rootKeyBytes = new byte[MasterKeySize];
                HKDF.DeriveKey(
                    HashAlgorithmName.SHA256,
                    ikm: masterKeyBytes,
                    output: rootKeyBytes,
                    salt: null,
                    info: System.Text.Encoding.UTF8.GetBytes(RootKeyInfo)
                );

                string rootKeyHash = CryptoHelpers.ComputeSha256Fingerprint(rootKeyBytes);
                Log.Information($"{LogTagServerRootKeyDerive} {LogMessageRootKeyDerived}",
                    membershipId, rootKeyHash);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(masterKeyBytes);
            }

            Result<EcliptixSystemIdentityKeys, KeySplittingFailure> deriveResult =
                await identityKeyDerivationService.DeriveIdentityKeysFromMasterKeyAsync(masterKeyHandle, membershipId);

            if (deriveResult.IsErr)
            {
                KeySplittingFailure error = deriveResult.UnwrapErr();
                return Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase>.Err(error);
            }

            EcliptixSystemIdentityKeys identityKeys = deriveResult.Unwrap();

            byte[] rootKeyToReturn = rootKeyBytes;
            rootKeyBytes = null;

            return Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase>.Ok((identityKeys, rootKeyToReturn));
        }
        catch (Exception ex)
        {
            return Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase>.Err(
                KeySplittingFailure.KeyDerivationFailed(ErrorMessageUnexpectedIdentityKeyDerivationError, ex));
        }
        finally
        {
            masterKeyHandle?.Dispose();
            if (rootKeyBytes != null)
            {
                CryptographicOperations.ZeroMemory(rootKeyBytes);
            }
        }
    }

    public async Task<Result<bool, FailureBase>> CheckSharesExistAsync(Guid membershipId)
    {
        try
        {
            Result<MasterKeyShareQueryRecord[], KeySplittingFailure> sharesResult =
                await RetrieveSharesAsync(membershipId);

            if (sharesResult.IsOk)
            {
                MasterKeyShareQueryRecord[] shares = sharesResult.Unwrap();
                return Result<bool, FailureBase>.Ok(shares.Length > 0);
            }

            KeySplittingFailure error = sharesResult.UnwrapErr();
            if (error.Type == KeySplittingFailureType.InsufficientShares)
            {
                return Result<bool, FailureBase>.Ok(false);
            }

            return Result<bool, FailureBase>.Err(error);
        }
        catch (Exception ex)
        {
            return Result<bool, FailureBase>.Err(
                KeySplittingFailure.KeyReconstructionFailed(ErrorMessageSharesCheckFailed, ex));
        }
    }

    public async Task<Result<dynamic, FailureBase>> RegenerateMasterKeySharesAsync(
        dynamic newSessionKey, Guid membershipId)
    {
        try
        {
            IActorRef masterKeySharePersistor = actorRegistry.Get(ActorIds.MasterKeySharePersistorActor);
            DeleteMasterKeySharesEvent deleteEvent = new(membershipId);

            Result<Unit, KeySplittingFailure> deleteResult =
                await masterKeySharePersistor.Ask<Result<Unit, KeySplittingFailure>>(
                    deleteEvent,
                    TimeSpan.FromSeconds(AskTimeoutSeconds));

            if (deleteResult.IsErr)
            {
                KeySplittingFailure error = deleteResult.UnwrapErr();
                Log.Warning("Failed to delete old master key shares during regeneration: {Error}", error.Message);
            }

            return await DeriveMasterKeyAndSplitAsync(newSessionKey, membershipId);
        }
        catch (Exception ex)
        {
            return Result<dynamic, FailureBase>.Err(
                KeySplittingFailure.KeyDerivationFailed($"Master key regeneration failed: {ex.Message}", ex));
        }
    }

    public async Task<Result<string, FailureBase>> ValidateMasterKeySharesAsync(
        dynamic sessionKeyHandle, Guid membershipId)
    {
        SodiumSecureMemoryHandle? expectedMasterKeyHandle = null;
        SodiumSecureMemoryHandle? actualMasterKeyHandle = null;

        try
        {
            Result<MasterKeyShareQueryRecord[], KeySplittingFailure> sharesResult = await RetrieveSharesAsync(membershipId);
            if (sharesResult.IsErr)
            {
                return Result<string, FailureBase>.Err(sharesResult.UnwrapErr());
            }

            MasterKeyShareQueryRecord[] shares = sharesResult.Unwrap();
            if (shares.Length == 0)
            {
                return Result<string, FailureBase>.Err(
                    KeySplittingFailure.KeyReconstructionFailed("No shares found for membership"));
            }

            await using EcliptixSchemaContext ctx = await dbContextFactory.CreateDbContextAsync();
            MembershipEntity? membership = await MembershipQueries.GetByUniqueId(ctx, membershipId);
            if (membership == null)
            {
                return Result<string, FailureBase>.Err(
                    KeySplittingFailure.KeyReconstructionFailed("Membership not found"));
            }

            int currentVersion = membership.CredentialsVersion;
            int storedVersion = shares[0].CredentialsVersion;

            Log.Information("[CREDENTIALS-VERSION-CHECK] Membership {MembershipId}: Current={Current}, Stored={Stored}",
                membershipId, currentVersion, storedVersion);

            if (currentVersion != storedVersion)
            {
                Log.Warning("[CREDENTIALS-VERSION-MISMATCH] Credentials version mismatch for membership {MembershipId}. Current: {Current}, Stored: {Stored}. Credentials changed since shares were created.",
                    membershipId, currentVersion, storedVersion);
                return Result<string, FailureBase>.Ok("mismatch");
            }

            Log.Information("[CREDENTIALS-VERSION-MATCH] Versions match for membership {MembershipId}. Proceeding with fingerprint validation.",
                membershipId);

            KeyDerivationOptions options = new()
            {
                MemorySize = Argon2MemorySize,
                Iterations = Argon2Iterations,
                DegreeOfParallelism = Argon2DegreeOfParallelism,
                UseHardwareEntropy = false,
                OutputLength = EnhancedKeyOutputLength
            };

            Result<SodiumSecureMemoryHandle, KeySplittingFailure> enhancedResult =
                await hardenedKeyDerivation.DeriveEnhancedMasterKeyHandleAsync(
                    sessionKeyHandle,
                    KeyDerivationContext,
                    options);

            if (enhancedResult.IsErr)
            {
                return Result<string, FailureBase>.Err(enhancedResult.UnwrapErr());
            }

            SodiumSecureMemoryHandle enhancedKeyHandle = enhancedResult.Unwrap();

            try
            {
                ByteString membershipIdentifier = Helpers.GuidToByteString(membershipId);
                Result<SodiumSecureMemoryHandle, SodiumFailure> expectedMasterKeyResult =
                    MasterKeyDerivation.DeriveMasterKeyHandle(enhancedKeyHandle, membershipIdentifier);

                if (expectedMasterKeyResult.IsErr)
                {
                    return Result<string, FailureBase>.Err(
                        KeySplittingFailure.KeyDerivationFailed($"Failed to derive expected master key: {expectedMasterKeyResult.UnwrapErr().Message}"));
                }

                expectedMasterKeyHandle = expectedMasterKeyResult.Unwrap();
            }
            finally
            {
                enhancedKeyHandle?.Dispose();
            }

            Result<dynamic, FailureBase> actualMasterKeyResult = await ReconstructMasterKeyAsync(membershipId);
            if (actualMasterKeyResult.IsErr)
            {
                return Result<string, FailureBase>.Err(actualMasterKeyResult.UnwrapErr());
            }

            actualMasterKeyHandle = (SodiumSecureMemoryHandle)actualMasterKeyResult.Unwrap();

            Result<byte[], SodiumFailure> expectedBytesResult = expectedMasterKeyHandle.ReadBytes(MasterKeySize);
            Result<byte[], SodiumFailure> actualBytesResult = actualMasterKeyHandle.ReadBytes(MasterKeySize);

            if (expectedBytesResult.IsErr || actualBytesResult.IsErr)
            {
                return Result<string, FailureBase>.Err(
                    KeySplittingFailure.KeyDerivationFailed("Failed to read master key bytes for comparison"));
            }

            byte[] expectedBytes = expectedBytesResult.Unwrap();
            byte[] actualBytes = actualBytesResult.Unwrap();

            try
            {
                string expectedFingerprint = CryptoHelpers.ComputeSha256Fingerprint(expectedBytes);
                string actualFingerprint = CryptoHelpers.ComputeSha256Fingerprint(actualBytes);

                bool matches = CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);

                Log.Information("[MASTER-KEY-VALIDATE] Fingerprint comparison for membership {MembershipId}. Expected: {Expected}, Actual: {Actual}, Match: {Match}",
                    membershipId, expectedFingerprint, actualFingerprint, matches);

                return Result<string, FailureBase>.Ok(matches ? "valid" : "mismatch");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(expectedBytes);
                CryptographicOperations.ZeroMemory(actualBytes);
            }
        }
        catch (Exception ex)
        {
            return Result<string, FailureBase>.Err(
                KeySplittingFailure.KeyDerivationFailed($"Master key validation failed: {ex.Message}", ex));
        }
        finally
        {
            expectedMasterKeyHandle?.Dispose();
            actualMasterKeyHandle?.Dispose();
        }
    }
}

internal class ShareMetadata
{
    public string ShareId { get; set; } = string.Empty;
    public Guid SessionId { get; set; }
    public DateTime CreatedAt { get; set; }
    public bool HasHmac { get; set; }
}
