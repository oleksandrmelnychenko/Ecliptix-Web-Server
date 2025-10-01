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
                Log.Error("Failed to derive enhanced master key: {Error}", enhancedResult.UnwrapErr().Message);
                return Result<dynamic, FailureBase>.Err(enhancedResult.UnwrapErr());
            }

            enhancedMasterKeyHandle = enhancedResult.Unwrap();

            ByteString membershipIdentifier = ByteString.CopyFrom(membershipId.ToByteArray());
            Result<SodiumSecureMemoryHandle, SodiumFailure> masterKeyResult =
                MasterKeyDerivation.DeriveMasterKeyHandle(enhancedMasterKeyHandle, membershipIdentifier);

            if (masterKeyResult.IsErr)
            {
                SodiumFailure sodiumError = masterKeyResult.UnwrapErr();
                Log.Error("Failed to derive master key: {Error}", sodiumError.Message);
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
                Log.Error("Failed to split master key: {Error}", splitResult.UnwrapErr().Message);
                return Result<dynamic, FailureBase>.Err(splitResult.UnwrapErr());
            }

            KeySplitResult keySplitResult = splitResult.Unwrap();

            Log.Information("Successfully derived and split master key for membership {MembershipId}", membershipId);

            // Persist shares to database
            Result<InsertMasterKeySharesResult, KeySplittingFailure> persistResult =
                await PersistSharesAsync(membershipId, keySplitResult);

            if (persistResult.IsErr)
            {
                Log.Error("Failed to persist master key shares for membership {MembershipId}: {Error}",
                    membershipId, persistResult.UnwrapErr().Message);
                return Result<dynamic, FailureBase>.Err(persistResult.UnwrapErr());
            }

            Log.Information("Successfully persisted {ShareCount} master key shares for membership {MembershipId}",
                keySplitResult.Shares.Length, membershipId);

            return Result<dynamic, FailureBase>.Ok(keySplitResult);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Unexpected error during master key derivation for membership {MembershipId}", membershipId);
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
                Log.Error("Failed to retrieve master key shares for membership {MembershipId}: {Error}",
                    membershipId, sharesResult.UnwrapErr().Message);
                return Result<dynamic, FailureBase>.Err(sharesResult.UnwrapErr());
            }

            MasterKeyShareQueryRecord[] shareRecords = sharesResult.Unwrap();

            if (shareRecords.Length < 3)
            {
                Log.Error("Insufficient shares to reconstruct master key for membership {MembershipId}. Found {ShareCount}, need at least 3",
                    membershipId, shareRecords.Length);
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
                    Log.Error("Failed to deserialize share metadata for membership {MembershipId}", membershipId);
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
                Log.Error("Failed to reconstruct master key for membership {MembershipId}: {Error}",
                    membershipId, reconstructResult.UnwrapErr().Message);
                return Result<dynamic, FailureBase>.Err(reconstructResult.UnwrapErr());
            }

            SodiumSecureMemoryHandle masterKeyHandle = reconstructResult.Unwrap();

            Log.Information("Successfully reconstructed master key for membership {MembershipId} from {ShareCount} shares",
                membershipId, shares.Count);

            return Result<dynamic, FailureBase>.Ok(masterKeyHandle);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Unexpected error during master key reconstruction for membership {MembershipId}", membershipId);
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
                Log.Error("MasterKeySharePersistorActor not found in registry");
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
            Log.Error("Timeout while persisting master key shares for membership {MembershipId}", membershipId);
            return Result<InsertMasterKeySharesResult, KeySplittingFailure>.Err(
                KeySplittingFailure.KeySplittingFailed("Timeout while persisting shares"));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error persisting master key shares for membership {MembershipId}", membershipId);
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
                Log.Error("MasterKeySharePersistorActor not found in registry");
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
            Log.Error("Timeout while retrieving master key shares for membership {MembershipId}", membershipId);
            return Result<MasterKeyShareQueryRecord[], KeySplittingFailure>.Err(
                KeySplittingFailure.KeyReconstructionFailed("Timeout while retrieving shares"));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error retrieving master key shares for membership {MembershipId}", membershipId);
            return Result<MasterKeyShareQueryRecord[], KeySplittingFailure>.Err(
                KeySplittingFailure.KeyReconstructionFailed($"Failed to retrieve shares: {ex.Message}", ex));
        }
    }

    public async Task<Result<dynamic, FailureBase>> DeriveIdentityKeysAsync(Guid membershipId)
    {
        SodiumSecureMemoryHandle? masterKeyHandle = null;
        try
        {
            // Reconstruct master key from shares
            Result<dynamic, FailureBase> reconstructResult = await ReconstructMasterKeyAsync(membershipId);
            if (reconstructResult.IsErr)
            {
                Log.Error("Failed to reconstruct master key for identity key derivation: {Error}",
                    reconstructResult.UnwrapErr().Message);
                return reconstructResult;
            }

            masterKeyHandle = (SodiumSecureMemoryHandle)reconstructResult.Unwrap();

            // Derive identity keys from master key
            Result<EcliptixSystemIdentityKeys, KeySplittingFailure> deriveResult =
                await _identityKeyDerivationService.DeriveIdentityKeysFromMasterKeyAsync(masterKeyHandle, membershipId);

            if (deriveResult.IsErr)
            {
                Log.Error("Failed to derive identity keys from master key for membership {MembershipId}: {Error}",
                    membershipId, deriveResult.UnwrapErr().Message);
                return Result<dynamic, FailureBase>.Err(deriveResult.UnwrapErr());
            }

            EcliptixSystemIdentityKeys identityKeys = deriveResult.Unwrap();

            Log.Information("Successfully derived identity keys from master key for membership {MembershipId}", membershipId);

            return Result<dynamic, FailureBase>.Ok(identityKeys);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Unexpected error during identity key derivation for membership {MembershipId}", membershipId);
            return Result<dynamic, FailureBase>.Err(
                KeySplittingFailure.KeyDerivationFailed("Unexpected error during identity key derivation", ex));
        }
        finally
        {
            masterKeyHandle?.Dispose();
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
