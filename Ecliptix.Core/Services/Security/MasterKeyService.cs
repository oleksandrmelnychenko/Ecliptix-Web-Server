using System.Security.Cryptography;
using Akka.Actor;
using Ecliptix.Core;
using Ecliptix.Core.Domain.Protocol;
using Ecliptix.Core.Services.KeyDerivation;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.QueryResults;
using Ecliptix.Domain.Services.Security;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Failures;
using Ecliptix.Utilities.Failures.Sodium;
using Google.Protobuf;
using Serilog;

namespace Ecliptix.Core.Services.Security;

public class MasterKeyService : IMasterKeyService
{
    private readonly IHardenedKeyDerivation _hardenedKeyDerivation;
    private readonly ISecretSharingService _secretSharingService;
    private readonly IEcliptixActorRegistry _actorRegistry;
    private readonly IIdentityKeyDerivationService _identityKeyDerivationService;

    public MasterKeyService(
        IHardenedKeyDerivation hardenedKeyDerivation,
        ISecretSharingService secretSharingService,
        IEcliptixActorRegistry actorRegistry,
        IIdentityKeyDerivationService identityKeyDerivationService)
    {
        _hardenedKeyDerivation = hardenedKeyDerivation;
        _secretSharingService = secretSharingService;
        _actorRegistry = actorRegistry;
        _identityKeyDerivationService = identityKeyDerivationService;
    }

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
                MemorySize = 262144,
                Iterations = 4,
                DegreeOfParallelism = 4,
                UseHardwareEntropy = false,
                OutputLength = 64
            };

            Result<SodiumSecureMemoryHandle, KeySplittingFailure> enhancedResult =
                await _hardenedKeyDerivation.DeriveEnhancedMasterKeyHandleAsync(
                    sessionKeyHandle,
                    "ecliptix-signin-session",
                    options);

            if (enhancedResult.IsErr)
            {

                return Result<dynamic, FailureBase>.Err(enhancedResult.UnwrapErr());
            }

            enhancedMasterKeyHandle = enhancedResult.Unwrap();

            ByteString membershipIdentifier = ByteString.CopyFrom(membershipId.ToByteArray());
            Result<SodiumSecureMemoryHandle, SodiumFailure> masterKeyResult =
                MasterKeyDerivation.DeriveMasterKeyHandle(enhancedMasterKeyHandle, membershipIdentifier);

            if (masterKeyResult.IsErr)
            {
                SodiumFailure sodiumError = masterKeyResult.UnwrapErr();

                return Result<dynamic, FailureBase>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"Master key derivation failed: {sodiumError.Message}"));
            }

            masterKeyHandle = masterKeyResult.Unwrap();

            // TODO: Implement HMAC key management for share authentication
            // For now, we're splitting without HMAC authentication
            Result<KeySplitResult, KeySplittingFailure> splitResult = await _secretSharingService.SplitKeyAsync(
                masterKeyHandle,
                threshold: 3,
                totalShares: 5,
                hmacKeyHandle: null);

            if (splitResult.IsErr)
            {

                return Result<dynamic, FailureBase>.Err(splitResult.UnwrapErr());
            }

            KeySplitResult keySplitResult = splitResult.Unwrap();

            // Persist shares to database
            Result<InsertMasterKeySharesResult, KeySplittingFailure> persistResult =
                await PersistSharesAsync(membershipId, keySplitResult);

            if (persistResult.IsErr)
            {

                return Result<dynamic, FailureBase>.Err(persistResult.UnwrapErr());
            }

            return Result<dynamic, FailureBase>.Ok(keySplitResult);
        }
        catch (Exception ex)
        {

            return Result<dynamic, FailureBase>.Err(
                KeySplittingFailure.KeyDerivationFailed("Unexpected error during master key derivation", ex));
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
            // Get shares from database
            Result<MasterKeyShareQueryRecord[], KeySplittingFailure> sharesResult =
                await RetrieveSharesAsync(membershipId);

            if (sharesResult.IsErr)
            {

                return Result<dynamic, FailureBase>.Err(sharesResult.UnwrapErr());
            }

            MasterKeyShareQueryRecord[] shareRecords = sharesResult.Unwrap();

            if (shareRecords.Length < 3)
            {

                return Result<dynamic, FailureBase>.Err(
                    KeySplittingFailure.KeyReconstructionFailed($"Insufficient shares: found {shareRecords.Length}, need at least 3"));
            }

            // Convert database records to KeyShare objects
            List<KeyShare> shares = new List<KeyShare>();
            foreach (MasterKeyShareQueryRecord record in shareRecords)
            {
                // Deserialize metadata
                var metadata = System.Text.Json.JsonSerializer.Deserialize<ShareMetadata>(record.ShareMetadata);
                if (metadata == null)
                {

                    return Result<dynamic, FailureBase>.Err(
                        KeySplittingFailure.KeyReconstructionFailed("Failed to deserialize share metadata"));
                }

                KeyShare share = new KeyShare(
                    shareData: record.EncryptedShare,
                    index: record.ShareIndex,
                    location: Enum.Parse<ShareLocation>(record.StorageLocation),
                    sessionId: metadata.SessionId
                );

                if (metadata.HasHmac)
                {
                    // TODO: Retrieve and set HMAC when implemented
                }

                shares.Add(share);
            }

            // Reconstruct the master key
            Result<SodiumSecureMemoryHandle, KeySplittingFailure> reconstructResult =
                await _secretSharingService.ReconstructKeyHandleAsync(shares.ToArray(), hmacKeyHandle: null);

            if (reconstructResult.IsErr)
            {

                return Result<dynamic, FailureBase>.Err(reconstructResult.UnwrapErr());
            }

            SodiumSecureMemoryHandle masterKeyHandle = reconstructResult.Unwrap();

            return Result<dynamic, FailureBase>.Ok(masterKeyHandle);
        }
        catch (Exception ex)
        {

            return Result<dynamic, FailureBase>.Err(
                KeySplittingFailure.KeyReconstructionFailed("Unexpected error during master key reconstruction", ex));
        }
    }

    private async Task<Result<InsertMasterKeySharesResult, KeySplittingFailure>> PersistSharesAsync(
        Guid membershipId, KeySplitResult keySplitResult)
    {
        try
        {
            IActorRef? masterKeySharePersistor = _actorRegistry.Get(ActorIds.MasterKeySharePersistorActor);
            if (masterKeySharePersistor == null)
            {

                return Result<InsertMasterKeySharesResult, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeySplittingFailed("Master key share persistor actor not available"));
            }

            // Convert KeyShare[] to ShareData[]
            List<ShareData> shareDataList = new List<ShareData>();
            foreach (KeyShare share in keySplitResult.Shares)
            {
                // Serialize share metadata
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

            InsertMasterKeySharesEvent insertEvent = new InsertMasterKeySharesEvent(
                membershipId,
                shareDataList
            );

            // Send to persistor and wait for result
            Result<InsertMasterKeySharesResult, KeySplittingFailure> result =
                await masterKeySharePersistor.Ask<Result<InsertMasterKeySharesResult, KeySplittingFailure>>(
                    insertEvent,
                    TimeSpan.FromSeconds(30));

            return result;
        }
        catch (TimeoutException)
        {

            return Result<InsertMasterKeySharesResult, KeySplittingFailure>.Err(
                KeySplittingFailure.KeySplittingFailed("Timeout while persisting shares"));
        }
        catch (Exception ex)
        {

            return Result<InsertMasterKeySharesResult, KeySplittingFailure>.Err(
                KeySplittingFailure.KeySplittingFailed($"Failed to persist shares: {ex.Message}", ex));
        }
    }

    private async Task<Result<MasterKeyShareQueryRecord[], KeySplittingFailure>> RetrieveSharesAsync(Guid membershipId)
    {
        try
        {
            IActorRef? masterKeySharePersistor = _actorRegistry.Get(ActorIds.MasterKeySharePersistorActor);
            if (masterKeySharePersistor == null)
            {

                return Result<MasterKeyShareQueryRecord[], KeySplittingFailure>.Err(
                    KeySplittingFailure.KeyReconstructionFailed("Master key share persistor actor not available"));
            }

            GetMasterKeySharesEvent getEvent = new GetMasterKeySharesEvent(membershipId);

            // Send to persistor and wait for result
            Result<MasterKeyShareQueryRecord[], KeySplittingFailure> result =
                await masterKeySharePersistor.Ask<Result<MasterKeyShareQueryRecord[], KeySplittingFailure>>(
                    getEvent,
                    TimeSpan.FromSeconds(30));

            return result;
        }
        catch (TimeoutException)
        {

            return Result<MasterKeyShareQueryRecord[], KeySplittingFailure>.Err(
                KeySplittingFailure.KeyReconstructionFailed("Timeout while retrieving shares"));
        }
        catch (Exception ex)
        {

            return Result<MasterKeyShareQueryRecord[], KeySplittingFailure>.Err(
                KeySplittingFailure.KeyReconstructionFailed($"Failed to retrieve shares: {ex.Message}", ex));
        }
    }

    public async Task<Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase>> DeriveIdentityKeysAsync(Guid membershipId)
    {
        SodiumSecureMemoryHandle? masterKeyHandle = null;
        byte[]? rootKeyBytes = null;
        try
        {
            // Reconstruct master key from shares
            Result<dynamic, FailureBase> reconstructResult = await ReconstructMasterKeyAsync(membershipId);
            if (reconstructResult.IsErr)
            {

                return Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase>.Err(reconstructResult.UnwrapErr());
            }

            masterKeyHandle = (SodiumSecureMemoryHandle)reconstructResult.Unwrap();

            // Derive root key from master key using HKDF with domain separation
            // Master key is 64 bytes, we derive a 32-byte root key for Double Ratchet
            Result<byte[], SodiumFailure> masterKeyReadResult = masterKeyHandle.ReadBytes(64);
            if (masterKeyReadResult.IsErr)
            {

                return Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"Failed to read master key bytes: {masterKeyReadResult.UnwrapErr().Message}"));
            }

            byte[] masterKeyBytes = masterKeyReadResult.Unwrap();
            try
            {
                rootKeyBytes = new byte[32];
                HKDF.DeriveKey(
                    HashAlgorithmName.SHA256,
                    ikm: masterKeyBytes,
                    output: rootKeyBytes,
                    salt: null,
                    info: "ecliptix-protocol-root-key"u8.ToArray()
                );
            }
            finally
            {
                CryptographicOperations.ZeroMemory(masterKeyBytes);
            }

            // Derive identity keys from master key
            Result<EcliptixSystemIdentityKeys, KeySplittingFailure> deriveResult =
                await _identityKeyDerivationService.DeriveIdentityKeysFromMasterKeyAsync(masterKeyHandle, membershipId);

            if (deriveResult.IsErr)
            {

                return Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase>.Err(deriveResult.UnwrapErr());
            }

            EcliptixSystemIdentityKeys identityKeys = deriveResult.Unwrap();

            byte[] rootKeyToReturn = rootKeyBytes;
            rootKeyBytes = null; // Prevent cleanup in finally

            return Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase>.Ok((identityKeys, rootKeyToReturn));
        }
        catch (Exception ex)
        {

            return Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase>.Err(
                KeySplittingFailure.KeyDerivationFailed("Unexpected error during identity key derivation", ex));
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
}

internal class ShareMetadata
{
    public string ShareId { get; set; } = string.Empty;
    public Guid SessionId { get; set; }
    public DateTime CreatedAt { get; set; }
    public bool HasHmac { get; set; }
}
