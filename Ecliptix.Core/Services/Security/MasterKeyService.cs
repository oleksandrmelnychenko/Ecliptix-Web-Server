using System.Security.Cryptography;
using Akka.Actor;
using Ecliptix.Core;
using Ecliptix.Core.Domain.Protocol;
using Ecliptix.Core.Services.KeyDerivation;
using Ecliptix.Domain.Memberships.ActorEvents.Account;
using Ecliptix.Domain.Memberships.ActorEvents.MasterKeyShares;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.QueryResults;
using Ecliptix.Domain.Services.Security;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Failures;
using Ecliptix.Utilities.Failures.Sodium;
using Google.Protobuf;
using Serilog;

namespace Ecliptix.Core.Services.Security;

internal sealed class MasterKeyService(
    ISecretSharingService secretSharingService,
    IEcliptixActorRegistry actorRegistry,
    IIdentityKeyDerivationService identityKeyDerivationService)
    : IMasterKeyService
{
    private const int Argon2MemorySize = 262144;
    private const int Argon2Iterations = 4;
    private const int Argon2DegreeOfParallelism = 4;
    private const int EnhancedKeyOutputLength = 64;
    private const int MasterKeySize = 32;
    private const int DefaultThreshold = 3;
    private const int DefaultTotalShares = 5;
    private const int AskTimeoutSeconds = 30;

    private const string KeyDerivationContext = "ecliptix-signin-session";
    private const string RootKeyInfo = "ecliptix-protocol-root-key";

    private const string ErrorMessageMasterKeyDerivationFailed = "Master key derivation failed";
    private const string ErrorMessageUnexpectedDerivationError = "Unexpected error during master key derivation";
    private const string ErrorMessageInsufficientShares = "Insufficient shares: found {0}, need at least 3";
    private const string ErrorMessageMetadataDeserializationFailed = "Failed to deserialize share metadata";

    private const string ErrorMessageUnexpectedReconstructionError =
        "Unexpected error during master key reconstruction";

    private const string ErrorMessagePersistSharesTimeout = "Timeout while persisting shares";
    private const string ErrorMessagePersistSharesFailed = "Failed to persist shares";
    private const string ErrorMessageRetrieveSharesTimeout = "Timeout while retrieving shares";
    private const string ErrorMessageRetrieveSharesFailed = "Failed to retrieve shares";
    private const string ErrorMessageMasterKeyReadFailed = "Failed to read master key bytes";

    private const string ErrorMessageUnexpectedIdentityKeyDerivationError =
        "Unexpected error during identity key derivation";

    private const string ErrorMessageSharesCheckFailed = "Unexpected error checking shares";

    public async Task<Result<dynamic, FailureBase>> GenerateRandomMasterKeyAndSplitAsync(Guid membershipId)
    {
        SodiumSecureMemoryHandle? masterKeyHandle = null;

        try
        {
            Result<bool, FailureBase> sharesExistResult = await CheckSharesExistAsync(membershipId);
            if (sharesExistResult.IsOk && sharesExistResult.Unwrap())
            {
                return Result<dynamic, FailureBase>.Err(
                    KeySplittingFailure.KeySplittingFailed("Master key shares already exist for this membership"));
            }

            Result<SodiumSecureMemoryHandle, SodiumFailure> allocateResult =
                SodiumSecureMemoryHandle.Allocate(MasterKeySize);

            if (allocateResult.IsErr)
            {
                SodiumFailure sodiumError = allocateResult.UnwrapErr();
                return Result<dynamic, FailureBase>.Err(
                    KeySplittingFailure.KeyDerivationFailed(
                        $"Failed to allocate master key handle: {sodiumError.Message}"));
            }

            masterKeyHandle = allocateResult.Unwrap();

            Result<byte[], SodiumFailure> randomBytesResult = SodiumInterop.GetRandomBytes(MasterKeySize);
            if (randomBytesResult.IsErr)
            {
                SodiumFailure sodiumError = randomBytesResult.UnwrapErr();
                return Result<dynamic, FailureBase>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"Failed to generate random bytes: {sodiumError.Message}"));
            }

            byte[] randomBytes = randomBytesResult.Unwrap();
            try
            {
                Result<Unit, SodiumFailure> writeResult = masterKeyHandle.Write(randomBytes);
                if (writeResult.IsErr)
                {
                    SodiumFailure sodiumError = writeResult.UnwrapErr();
                    return Result<dynamic, FailureBase>.Err(
                        KeySplittingFailure.KeyDerivationFailed(
                            $"Failed to write random bytes to handle: {sodiumError.Message}"));
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(randomBytes);
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

            Log.Information("[SERVER-MASTERKEY-GENERATE] Master key shares persisted successfully. MembershipId: {0}",
                membershipId);

            return Result<dynamic, FailureBase>.Ok(keySplitResult);
        }
        catch (Exception ex)
        {
            return Result<dynamic, FailureBase>.Err(
                KeySplittingFailure.KeyDerivationFailed($"Unexpected error during master key generation: {ex.Message}",
                    ex));
        }
        finally
        {
            masterKeyHandle?.Dispose();
        }
    }

    public async Task<Result<dynamic, FailureBase>> SplitAndStoreMasterKeyAsync(byte[] masterKeyBytes,
        Guid membershipId, bool allowOverwrite = false)
    {
        if (masterKeyBytes.Length != MasterKeySize)
        {
            return Result<dynamic, FailureBase>.Err(
                KeySplittingFailure.KeySplittingFailed($"Invalid master key size. Expected {MasterKeySize} bytes"));
        }

        SodiumSecureMemoryHandle? masterKeyHandle = null;

        try
        {
            Result<bool, FailureBase> sharesExistResult = await CheckSharesExistAsync(membershipId);

            if (sharesExistResult.IsOk && sharesExistResult.Unwrap())
            {
                if (!allowOverwrite)
                {
                    return Result<dynamic, FailureBase>.Err(
                        KeySplittingFailure.KeySplittingFailed("Master key shares already exist for this membership"));
                }

                Log.Information(
                    "[SERVER-MASTERKEY-OVERWRITE] Deleting existing master key shares for MembershipId: {0}",
                    membershipId);
                Result<Unit, KeySplittingFailure> deleteResult = await DeleteExistingSharesAsync(membershipId);

                if (deleteResult.IsErr)
                {
                    Log.Error(
                        "[SERVER-MASTERKEY-OVERWRITE] Failed to delete existing shares for MembershipId: {0}, Error: {1}",
                        membershipId, deleteResult.UnwrapErr().Message);
                    return Result<dynamic, FailureBase>.Err(deleteResult.UnwrapErr());
                }

                Log.Information(
                    "[SERVER-MASTERKEY-OVERWRITE] Successfully deleted existing shares for MembershipId: {0}",
                    membershipId);
            }

            Result<SodiumSecureMemoryHandle, SodiumFailure> allocateResult =
                SodiumSecureMemoryHandle.Allocate(MasterKeySize);

            if (allocateResult.IsErr)
            {
                SodiumFailure sodiumError = allocateResult.UnwrapErr();
                return Result<dynamic, FailureBase>.Err(
                    KeySplittingFailure.KeyDerivationFailed(
                        $"Failed to allocate master key handle: {sodiumError.Message}"));
            }

            masterKeyHandle = allocateResult.Unwrap();

            Result<Unit, SodiumFailure> writeResult = masterKeyHandle.Write(masterKeyBytes);
            if (writeResult.IsErr)
            {
                SodiumFailure sodiumError = writeResult.UnwrapErr();
                return Result<dynamic, FailureBase>.Err(
                    KeySplittingFailure.KeyDerivationFailed(
                        $"Failed to write master key to handle: {sodiumError.Message}"));
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

            Log.Information("[SERVER-MASTERKEY-SPLIT] Master key shares persisted successfully. MembershipId: {0}",
                membershipId);

            return Result<dynamic, FailureBase>.Ok(keySplitResult);
        }
        catch (Exception ex)
        {
            return Result<dynamic, FailureBase>.Err(
                KeySplittingFailure.KeyDerivationFailed($"Unexpected error during master key splitting: {ex.Message}",
                    ex));
        }
        finally
        {
            masterKeyHandle?.Dispose();
        }
    }

    public async Task<Result<bool, FailureBase>> EnsureMasterKeyExistsAsync(Guid membershipId)
    {
        try
        {
            Result<bool, FailureBase> sharesExistResult = await CheckSharesExistAsync(membershipId);
            if (sharesExistResult.IsErr)
            {
                return Result<bool, FailureBase>.Err(sharesExistResult.UnwrapErr());
            }

            if (sharesExistResult.Unwrap())
            {
                Log.Debug("[SERVER-MASTERKEY-ENSURE] Master key shares already exist for MembershipId: {0}",
                    membershipId);
                return Result<bool, FailureBase>.Ok(true);
            }

            Log.Information(
                "[SERVER-MASTERKEY-ENSURE] No master key shares found, generating new master key for MembershipId: {0}",
                membershipId);
            Result<dynamic, FailureBase> generateResult = await GenerateRandomMasterKeyAndSplitAsync(membershipId);

            return generateResult.IsErr
                ? Result<bool, FailureBase>.Err(generateResult.UnwrapErr())
                : Result<bool, FailureBase>.Ok(true);
        }
        catch (Exception ex)
        {
            return Result<bool, FailureBase>.Err(
                KeySplittingFailure.KeyDerivationFailed($"Unexpected error ensuring master key exists: {ex.Message}",
                    ex));
        }
    }

    public async Task<Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase>> DeriveIdentityKeysAsync(
        Guid membershipId)
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
                rootKeyBytes = new byte[MasterKeySize];
                HKDF.DeriveKey(
                    HashAlgorithmName.SHA256,
                    ikm: masterKeyBytes,
                    output: rootKeyBytes,
                    salt: null,
                    info: System.Text.Encoding.UTF8.GetBytes(RootKeyInfo)
                );
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


    private async Task<Result<dynamic, FailureBase>> ReconstructMasterKeyAsync(Guid membershipId)
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
                    KeySplittingFailure.KeyReconstructionFailed(string.Format(ErrorMessageInsufficientShares,
                        shareRecords.Length)));
            }

            List<KeyShare> shares = [];
            foreach (MasterKeyShareQueryRecord record in shareRecords)
            {
                ShareMetadata? metadata =
                    System.Text.Json.JsonSerializer.Deserialize<ShareMetadata>(record.ShareMetadata);
                if (metadata == null)
                {
                    return Result<dynamic, FailureBase>.Err(
                        KeySplittingFailure.KeyReconstructionFailed(ErrorMessageMetadataDeserializationFailed));
                }

                KeyShare share = new(
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

            Result<InsertMasterKeySharesResult, MasterKeyFailure> result =
                await masterKeySharePersistor.Ask<Result<InsertMasterKeySharesResult, MasterKeyFailure>>(
                    insertEvent,
                    TimeSpan.FromSeconds(AskTimeoutSeconds));

            return result.Match(
                ok => Result<InsertMasterKeySharesResult, KeySplittingFailure>.Ok(ok),
                err => Result<InsertMasterKeySharesResult, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeySplittingFailed($"{ErrorMessagePersistSharesFailed}: {err.Message}",
                        err.InnerException)));
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
            GetMasterKeySharesEvent getEvent = new(membershipId);

            Result<MasterKeyShareQueryRecord[], MasterKeyFailure> result =
                await masterKeySharePersistor.Ask<Result<MasterKeyShareQueryRecord[], MasterKeyFailure>>(
                    getEvent,
                    TimeSpan.FromSeconds(AskTimeoutSeconds));

            return result.Match(
                ok => Result<MasterKeyShareQueryRecord[], KeySplittingFailure>.Ok(ok),
                err => Result<MasterKeyShareQueryRecord[], KeySplittingFailure>.Err(
                    KeySplittingFailure.KeyReconstructionFailed($"{ErrorMessageRetrieveSharesFailed}: {err.Message}",
                        err.InnerException)));
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

    private async Task<Result<Unit, KeySplittingFailure>> DeleteExistingSharesAsync(Guid membershipId)
    {
        try
        {
            IActorRef masterKeySharePersistor = actorRegistry.Get(ActorIds.MasterKeySharePersistorActor);
            DeleteMasterKeySharesEvent deleteEvent = new(membershipId);

            Result<Unit, MasterKeyFailure> result =
                await masterKeySharePersistor.Ask<Result<Unit, MasterKeyFailure>>(
                    deleteEvent,
                    TimeSpan.FromSeconds(AskTimeoutSeconds));

            return result.Match(
                ok => Result<Unit, KeySplittingFailure>.Ok(ok),
                err => Result<Unit, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeySplittingFailed($"Failed to delete existing shares: {err.Message}",
                        err.InnerException)));
        }
        catch (TimeoutException)
        {
            return Result<Unit, KeySplittingFailure>.Err(
                KeySplittingFailure.KeySplittingFailed("Timeout while deleting existing shares"));
        }
        catch (Exception ex)
        {
            return Result<Unit, KeySplittingFailure>.Err(
                KeySplittingFailure.KeySplittingFailed($"Failed to delete existing shares: {ex.Message}", ex));
        }
    }

    public async Task<Result<dynamic, FailureBase>> GetMasterKeyHandleAsync(Guid membershipId)
    {
        Log.Information("[MASTER-KEY-SERVICE] Retrieving master key handle for MembershipId: {0}", membershipId);

        try
        {
            Result<dynamic, FailureBase> reconstructResult = await ReconstructMasterKeyAsync(membershipId);
            if (reconstructResult.IsErr)
            {
                FailureBase error = reconstructResult.UnwrapErr();
                Log.Warning("[MASTER-KEY-SERVICE] Failed to reconstruct master key: {0}", error.Message);
                return Result<dynamic, FailureBase>.Err(error);
            }

            SodiumSecureMemoryHandle masterKeyHandle = (SodiumSecureMemoryHandle)reconstructResult.Unwrap();

            Log.Debug("[MASTER-KEY-SERVICE] Master key handle retrieved successfully for MembershipId: {0}",
                membershipId);

            return Result<dynamic, FailureBase>.Ok(masterKeyHandle);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[MASTER-KEY-SERVICE] Unexpected error retrieving master key handle for MembershipId: {0}",
                membershipId);
            return Result<dynamic, FailureBase>.Err(
                KeySplittingFailure.KeyReconstructionFailed(
                    $"Unexpected error retrieving master key handle: {ex.Message}", ex));
        }
    }
}
