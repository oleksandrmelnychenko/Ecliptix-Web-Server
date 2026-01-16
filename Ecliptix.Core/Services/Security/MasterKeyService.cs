using System.Buffers.Binary;
using System.Security.Cryptography;
using Akka.Actor;
using Ecliptix.Core.Services.KeyDerivation;
using Ecliptix.IdentityAccess.Domain.Actors.Membership;
using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.IdentityAccess.Domain.Persistors.CompiledQueries;
using Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;
using Ecliptix.IdentityAccess.Domain.Persistors.QueryResults;
using Ecliptix.IdentityAccess.Domain.Schema;
using Ecliptix.IdentityAccess.Domain.Services;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Configuration;
using Ecliptix.SharedKernel.Actors;
using Ecliptix.SharedKernel.Failures;
using Ecliptix.SharedKernel.Failures.Sodium;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Serilog;

namespace Ecliptix.Core.Services.Security;

internal sealed class MasterKeyService(
    ISecretSharingService secretSharingService,
    IEcliptixActorRegistry actorRegistry,
    IDbContextFactory<EcliptixSchemaContext> dbContextFactory,
    IIdentityKeyDerivationService identityKeyDerivationService,
    IOptionsMonitor<SecurityConfiguration> securityConfig)
    : IMasterKeyService
{
    private readonly int _masterKeySize = securityConfig.CurrentValue.Cryptography.MasterKeySize;
    private readonly int _defaultThreshold = securityConfig.CurrentValue.Cryptography.DefaultThreshold;
    private readonly int _defaultTotalShares = securityConfig.CurrentValue.Cryptography.DefaultTotalShares;
    private readonly int _askTimeoutSeconds = securityConfig.CurrentValue.Cryptography.AskTimeoutSeconds;

    private const string ErrorMessageInsufficientShares = "Insufficient shares: found {0}, need at least 3";
    private const string ErrorMessageMetadataDeserializationFailed = "Failed to deserialize share metadata";

    private const string ErrorMessageUnexpectedReconstructionError =
        "Unexpected error during master key reconstruction";

    private const string ErrorMessagePersistSharesTimeout = "Timeout while persisting shares";
    private const string ErrorMessagePersistSharesFailed = "Failed to persist shares";
    private const string ErrorMessageRetrieveSharesTimeout = "Timeout while retrieving shares";
    private const string ErrorMessageRetrieveSharesFailed = "Failed to retrieve shares";
    private const string ErrorMessageMasterKeyReadFailed = "Failed to read master key bytes";
    private const string ErrorMessageCredentialsMissing = "Credentials not found for account";
    private const string ErrorMessageCredentialsVersionMismatch = "Master key share credentials version mismatch";
    private const string ErrorMessageShareDecryptFailed = "Failed to decrypt master key share";
    private const string ErrorMessageInvalidEncryptionMetadata = "Invalid share encryption metadata";

    private const string ErrorMessageUnexpectedIdentityKeyDerivationError =
        "Unexpected error during identity key derivation";

    private const string ErrorMessageSharesCheckFailed = "Unexpected error checking shares";

    private const int MaskingKeyLength = 32;
    private const int ShareEncryptionVersion = 1;

    private static ReadOnlySpan<byte> ShareEncryptionInfo =>
        "ecliptix-master-key-share-enc:v1"u8;

    public async Task<Result<Unit, FailureBase>> GenerateRandomMasterKeyAndSplitAsync(Guid accountId)
    {
        SodiumSecureMemoryHandle? masterKeyHandle = null;
        KeySplitResult? keySplitResult = null;
        SodiumSecureMemoryHandle? hmacKeyHandle = null;
        byte[]? encryptionKey = null;
        CredentialsRecord? credentials = null;

        try
        {
            Result<bool, FailureBase> sharesExistResult = await CheckSharesExistAsync(accountId);
            if (sharesExistResult.IsOk && sharesExistResult.Unwrap())
            {
                return Result<Unit, FailureBase>.Err(
                    KeySplittingFailure.KeySplittingFailed("Master key shares already exist for this membership"));
            }

            Result<SodiumSecureMemoryHandle, SodiumFailure> allocateResult =
                SodiumSecureMemoryHandle.Allocate(_masterKeySize);

            if (allocateResult.IsErr)
            {
                SodiumFailure sodiumError = allocateResult.UnwrapErr();
                return Result<Unit, FailureBase>.Err(
                    KeySplittingFailure.KeyDerivationFailed(
                        $"Failed to allocate master key handle: {sodiumError.Message}"));
            }

            masterKeyHandle = allocateResult.Unwrap();

            Result<CredentialsRecord, FailureBase> credentialsResult = await GetCredentialsAsync(accountId);
            if (credentialsResult.IsErr)
            {
                return Result<Unit, FailureBase>.Err(credentialsResult.UnwrapErr());
            }

            credentials = credentialsResult.Unwrap();

            Result<SodiumSecureMemoryHandle, FailureBase> hmacHandleResult =
                CreateHmacKeyHandle(credentials.MaskingKey);
            if (hmacHandleResult.IsErr)
            {
                return Result<Unit, FailureBase>.Err(hmacHandleResult.UnwrapErr());
            }

            hmacKeyHandle = hmacHandleResult.Unwrap();
            encryptionKey = DeriveShareEncryptionKey(credentials.MaskingKey, accountId);

            Result<byte[], SodiumFailure> randomBytesResult = SodiumInterop.GetRandomBytes(_masterKeySize);
            if (randomBytesResult.IsErr)
            {
                SodiumFailure sodiumError = randomBytesResult.UnwrapErr();
                return Result<Unit, FailureBase>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"Failed to generate random bytes: {sodiumError.Message}"));
            }

            byte[] randomBytes = randomBytesResult.Unwrap();
            try
            {
                Result<Unit, SodiumFailure> writeResult = masterKeyHandle.Write(randomBytes);
                if (writeResult.IsErr)
                {
                    SodiumFailure sodiumError = writeResult.UnwrapErr();
                    return Result<Unit, FailureBase>.Err(
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
                threshold: _defaultThreshold,
                totalShares: _defaultTotalShares,
                hmacKeyHandle: hmacKeyHandle);

            if (splitResult.IsErr)
            {
                KeySplittingFailure error = splitResult.UnwrapErr();
                return Result<Unit, FailureBase>.Err(error);
            }

            keySplitResult = splitResult.Unwrap();

            Result<InsertMasterKeySharesResult, KeySplittingFailure> persistResult =
                await PersistSharesAsync(accountId, keySplitResult, credentials.Version, encryptionKey, hasHmac: true);

            if (persistResult.IsErr)
            {
                KeySplittingFailure error = persistResult.UnwrapErr();
                return Result<Unit, FailureBase>.Err(error);
            }

            return Result<Unit, FailureBase>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, FailureBase>.Err(
                KeySplittingFailure.KeyDerivationFailed($"Unexpected error during master key generation: {ex.Message}",
                    ex));
        }
        finally
        {
            keySplitResult?.Dispose();
            masterKeyHandle?.Dispose();
            hmacKeyHandle?.Dispose();
            if (encryptionKey != null)
            {
                CryptographicOperations.ZeroMemory(encryptionKey);
            }

            if (credentials != null)
            {
                CryptographicOperations.ZeroMemory(credentials.MaskingKey);
                CryptographicOperations.ZeroMemory(credentials.SecureKey);
            }
        }
    }

    public async Task<Result<Unit, FailureBase>> SplitAndStoreMasterKeyAsync(byte[] masterKeyBytes,
        Guid accountId, bool allowOverwrite = false)
    {
        if (masterKeyBytes.Length != _masterKeySize)
        {
            return Result<Unit, FailureBase>.Err(
                KeySplittingFailure.KeySplittingFailed($"Invalid master key size. Expected {_masterKeySize} bytes"));
        }

        SodiumSecureMemoryHandle? masterKeyHandle = null;
        KeySplitResult? keySplitResult = null;
        SodiumSecureMemoryHandle? hmacKeyHandle = null;
        byte[]? encryptionKey = null;
        CredentialsRecord? credentials = null;

        try
        {
            Result<bool, FailureBase> sharesExistResult = await CheckSharesExistAsync(accountId);

            if (sharesExistResult.IsOk && sharesExistResult.Unwrap())
            {
                if (!allowOverwrite)
                {
                    return Result<Unit, FailureBase>.Err(
                        KeySplittingFailure.KeySplittingFailed("Master key shares already exist for this account"));
                }

                Result<Unit, KeySplittingFailure> deleteResult = await DeleteExistingSharesAsync(accountId);

                if (deleteResult.IsErr)
                {
                    return Result<Unit, FailureBase>.Err(deleteResult.UnwrapErr());
                }
            }

            Result<SodiumSecureMemoryHandle, SodiumFailure> allocateResult =
                SodiumSecureMemoryHandle.Allocate(_masterKeySize);

            if (allocateResult.IsErr)
            {
                SodiumFailure sodiumError = allocateResult.UnwrapErr();
                return Result<Unit, FailureBase>.Err(
                    KeySplittingFailure.KeyDerivationFailed(
                        $"Failed to allocate master key handle: {sodiumError.Message}"));
            }

            masterKeyHandle = allocateResult.Unwrap();

            Result<CredentialsRecord, FailureBase> credentialsResult = await GetCredentialsAsync(accountId);
            if (credentialsResult.IsErr)
            {
                return Result<Unit, FailureBase>.Err(credentialsResult.UnwrapErr());
            }

            credentials = credentialsResult.Unwrap();

            Result<SodiumSecureMemoryHandle, FailureBase> hmacHandleResult =
                CreateHmacKeyHandle(credentials.MaskingKey);
            if (hmacHandleResult.IsErr)
            {
                return Result<Unit, FailureBase>.Err(hmacHandleResult.UnwrapErr());
            }

            hmacKeyHandle = hmacHandleResult.Unwrap();
            encryptionKey = DeriveShareEncryptionKey(credentials.MaskingKey, accountId);

            Result<Unit, SodiumFailure> writeResult = masterKeyHandle.Write(masterKeyBytes);
            if (writeResult.IsErr)
            {
                SodiumFailure sodiumError = writeResult.UnwrapErr();
                return Result<Unit, FailureBase>.Err(
                    KeySplittingFailure.KeyDerivationFailed(
                        $"Failed to write master key to handle: {sodiumError.Message}"));
            }

            Result<KeySplitResult, KeySplittingFailure> splitResult = await secretSharingService.SplitKeyAsync(
                masterKeyHandle,
                threshold: _defaultThreshold,
                totalShares: _defaultTotalShares,
                hmacKeyHandle: hmacKeyHandle);

            if (splitResult.IsErr)
            {
                KeySplittingFailure error = splitResult.UnwrapErr();
                return Result<Unit, FailureBase>.Err(error);
            }

            keySplitResult = splitResult.Unwrap();

            Result<InsertMasterKeySharesResult, KeySplittingFailure> persistResult =
                await PersistSharesAsync(accountId, keySplitResult, credentials.Version, encryptionKey, hasHmac: true);

            if (persistResult.IsErr)
            {
                KeySplittingFailure error = persistResult.UnwrapErr();
                return Result<Unit, FailureBase>.Err(error);
            }

            Log.Information("[SERVER-MASTERKEY-SPLIT] Master key shares persisted successfully. AccountId: {AccountId}",
                accountId);

            return Result<Unit, FailureBase>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, FailureBase>.Err(
                KeySplittingFailure.KeyDerivationFailed($"Unexpected error during master key splitting: {ex.Message}",
                    ex));
        }
        finally
        {
            keySplitResult?.Dispose();
            masterKeyHandle?.Dispose();
            hmacKeyHandle?.Dispose();
            if (encryptionKey != null)
            {
                CryptographicOperations.ZeroMemory(encryptionKey);
            }

            if (credentials != null)
            {
                CryptographicOperations.ZeroMemory(credentials.MaskingKey);
                CryptographicOperations.ZeroMemory(credentials.SecureKey);
            }
        }
    }

    public async Task<Result<bool, FailureBase>> EnsureMasterKeyExistsAsync(Guid accountId)
    {
        try
        {
            Result<bool, FailureBase> sharesExistResult = await CheckSharesExistAsync(accountId);
            if (sharesExistResult.IsErr)
            {
                return Result<bool, FailureBase>.Err(sharesExistResult.UnwrapErr());
            }

            if (sharesExistResult.Unwrap())
            {
                return Result<bool, FailureBase>.Ok(true);
            }

            Result<Unit, FailureBase> generateResult = await GenerateRandomMasterKeyAndSplitAsync(accountId);

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
        Guid accountId)
    {
        Result<byte[], FailureBase> rootResult = await DeriveRootKeyAsync(accountId);
        if (rootResult.IsErr)
        {
            return Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase>.Err(rootResult.UnwrapErr());
        }

        byte[]? rootKeyBytes = rootResult.Unwrap();
        SodiumSecureMemoryHandle? masterKeyHandle = null;
        try
        {
            Result<SodiumSecureMemoryHandle, FailureBase> reconstructResult = await ReconstructMasterKeyAsync(accountId);
            if (reconstructResult.IsErr)
            {
                FailureBase error = reconstructResult.UnwrapErr();
                return Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase>.Err(error);
            }

            masterKeyHandle = reconstructResult.Unwrap();

            Result<EcliptixSystemIdentityKeys, KeySplittingFailure> deriveResult =
                await identityKeyDerivationService.DeriveIdentityKeysFromMasterKeyAsync(masterKeyHandle, accountId);

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

    public async Task<Result<byte[], FailureBase>> DeriveRootKeyAsync(Guid accountId)
    {
        Result<(byte[] RootKey, byte[] MasterKeyFingerprint), FailureBase> deriveResult =
            await DeriveRootKeyAndFingerprintAsync(accountId);
        if (deriveResult.IsErr)
        {
            return Result<byte[], FailureBase>.Err(deriveResult.UnwrapErr());
        }

        (byte[] rootKey, byte[] fingerprint) = deriveResult.Unwrap();
        CryptographicOperations.ZeroMemory(fingerprint);
        return Result<byte[], FailureBase>.Ok(rootKey);
    }

    public async Task<Result<(byte[] RootKey, byte[] MasterKeyFingerprint), FailureBase>>
        DeriveRootKeyAndFingerprintAsync(Guid accountId)
    {
        SodiumSecureMemoryHandle? masterKeyHandle = null;
        byte[]? masterKeyBytes = null;
        try
        {
            Result<SodiumSecureMemoryHandle, FailureBase> reconstructResult = await ReconstructMasterKeyAsync(accountId);
            if (reconstructResult.IsErr)
            {
                return Result<(byte[] RootKey, byte[] MasterKeyFingerprint), FailureBase>.Err(
                    reconstructResult.UnwrapErr());
            }

            masterKeyHandle = reconstructResult.Unwrap();

            Result<byte[], SodiumFailure> masterKeyReadResult = masterKeyHandle.ReadBytes(_masterKeySize);
            if (masterKeyReadResult.IsErr)
            {
                SodiumFailure error = masterKeyReadResult.UnwrapErr();
                return Result<(byte[] RootKey, byte[] MasterKeyFingerprint), FailureBase>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"{ErrorMessageMasterKeyReadFailed}: {error.Message}"));
            }

            masterKeyBytes = masterKeyReadResult.Unwrap();
            try
            {
                byte[] rootKeyBytes = new byte[_masterKeySize];

                const int guidSize = 16;
                const int infoPrefixLength = 28;
                const int guidStringLength = 36;
                const int totalInfoLength = infoPrefixLength + guidStringLength;

                Span<byte> saltBytes = stackalloc byte[guidSize];
                accountId.TryWriteBytes(saltBytes);

                Span<char> guidChars = stackalloc char[guidStringLength];
                accountId.TryFormat(guidChars, out _);

                Span<byte> infoBytes = stackalloc byte[totalInfoLength];
                "ecliptix-protocol-root-key:v1:"u8.CopyTo(infoBytes);
                System.Text.Encoding.UTF8.GetBytes(guidChars, infoBytes[infoPrefixLength..]);

                HKDF.DeriveKey(
                    HashAlgorithmName.SHA512,
                    ikm: masterKeyBytes,
                    output: rootKeyBytes,
                    salt: saltBytes,
                    info: infoBytes);

                byte[] fingerprintBytes = DeriveMasterKeyFingerprint(masterKeyBytes, accountId);

                return Result<(byte[] RootKey, byte[] MasterKeyFingerprint), FailureBase>.Ok(
                    (rootKeyBytes, fingerprintBytes));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(masterKeyBytes);
            }
        }
        catch (Exception ex)
        {
            return Result<(byte[] RootKey, byte[] MasterKeyFingerprint), FailureBase>.Err(
                KeySplittingFailure.KeyDerivationFailed(ErrorMessageUnexpectedIdentityKeyDerivationError, ex));
        }
        finally
        {
            masterKeyHandle?.Dispose();
            if (masterKeyBytes != null)
            {
                CryptographicOperations.ZeroMemory(masterKeyBytes);
            }
        }
    }

    private static byte[] DeriveMasterKeyFingerprint(byte[] masterKeyBytes, Guid accountId)
    {
        const int infoPrefixLength = 36;
        const int guidStringLength = 36;
        const int totalInfoLength = infoPrefixLength + guidStringLength;
        const int hmacOutputSize = 32;

        Span<char> guidChars = stackalloc char[guidStringLength];
        accountId.TryFormat(guidChars, out _);

        Span<byte> infoBytes = stackalloc byte[totalInfoLength];
        "ecliptix-master-key-fingerprint:v1:"u8.CopyTo(infoBytes);
        System.Text.Encoding.UTF8.GetBytes(guidChars, infoBytes[infoPrefixLength..]);

        byte[] fingerprint = new byte[hmacOutputSize];
        using HMACSHA256 hmac = new(masterKeyBytes);
        hmac.TryComputeHash(infoBytes, fingerprint, out _);
        return fingerprint;
    }

    public async Task<Result<bool, FailureBase>> CheckSharesExistAsync(Guid accountId)
    {
        try
        {
            Result<MasterKeyShareQueryRecord[], KeySplittingFailure> sharesResult =
                await RetrieveSharesAsync(accountId);

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

    private async Task<Result<SodiumSecureMemoryHandle, FailureBase>> ReconstructMasterKeyAsync(Guid accountId)
    {
        SodiumSecureMemoryHandle? hmacKeyHandle = null;
        byte[]? encryptionKey = null;
        CredentialsRecord? credentials = null;
        List<KeyShare>? shares = null;

        try
        {
            Result<MasterKeyShareQueryRecord[], KeySplittingFailure> sharesResult =
                await RetrieveSharesAsync(accountId);

            if (sharesResult.IsErr)
            {
                KeySplittingFailure error = sharesResult.UnwrapErr();
                return Result<SodiumSecureMemoryHandle, FailureBase>.Err(error);
            }

            MasterKeyShareQueryRecord[] shareRecords = sharesResult.Unwrap();

            if (shareRecords.Length < _defaultThreshold)
            {
                return Result<SodiumSecureMemoryHandle, FailureBase>.Err(
                    KeySplittingFailure.KeyReconstructionFailed(string.Format(ErrorMessageInsufficientShares,
                        shareRecords.Length)));
            }

            Result<CredentialsRecord, FailureBase> credentialsResult = await GetCredentialsAsync(accountId);
            if (credentialsResult.IsErr)
            {
                return Result<SodiumSecureMemoryHandle, FailureBase>.Err(credentialsResult.UnwrapErr());
            }

            credentials = credentialsResult.Unwrap();

            Result<Unit, FailureBase> maskingKeyValidation = ValidateMaskingKey(credentials.MaskingKey);
            if (maskingKeyValidation.IsErr)
            {
                return Result<SodiumSecureMemoryHandle, FailureBase>.Err(maskingKeyValidation.UnwrapErr());
            }

            int expectedVersion = shareRecords[0].CredentialsVersion;
            if (shareRecords.Any(record => record.CredentialsVersion != expectedVersion))
            {
                return Result<SodiumSecureMemoryHandle, FailureBase>.Err(
                    KeySplittingFailure.InvalidShareData(ErrorMessageCredentialsVersionMismatch));
            }

            if (expectedVersion != credentials.Version)
            {
                return Result<SodiumSecureMemoryHandle, FailureBase>.Err(
                    KeySplittingFailure.KeyReconstructionFailed(ErrorMessageCredentialsVersionMismatch));
            }

            shares = new List<KeyShare>(shareRecords.Length);
            bool? hasHmac = null;
            foreach (MasterKeyShareQueryRecord record in shareRecords)
            {
                ShareMetadata? metadata =
                    System.Text.Json.JsonSerializer.Deserialize<ShareMetadata>(record.ShareMetadata);
                if (metadata == null)
                {
                    return Result<SodiumSecureMemoryHandle, FailureBase>.Err(
                        KeySplittingFailure.KeyReconstructionFailed(ErrorMessageMetadataDeserializationFailed));
                }

                bool metadataHasHmac = metadata.HasHmac;
                if (hasHmac.HasValue && hasHmac.Value != metadataHasHmac)
                {
                    return Result<SodiumSecureMemoryHandle, FailureBase>.Err(
                        KeySplittingFailure.InvalidShareData("Share HMAC metadata mismatch"));
                }

                hasHmac = metadataHasHmac;

                byte[] shareBytes = record.EncryptedShare;
                bool hasNonce = !string.IsNullOrWhiteSpace(metadata.EncryptionNonce);
                bool hasTag = !string.IsNullOrWhiteSpace(metadata.EncryptionTag);

                if (hasNonce || hasTag)
                {
                    if (!hasNonce || !hasTag)
                    {
                        return Result<SodiumSecureMemoryHandle, FailureBase>.Err(
                            KeySplittingFailure.InvalidShareData(ErrorMessageInvalidEncryptionMetadata));
                    }

                    if (metadata.EncryptionVersion != ShareEncryptionVersion)
                    {
                        return Result<SodiumSecureMemoryHandle, FailureBase>.Err(
                            KeySplittingFailure.InvalidShareData(
                                $"Unsupported share encryption version: {metadata.EncryptionVersion}"));
                    }

                    encryptionKey ??= DeriveShareEncryptionKey(credentials.MaskingKey, accountId);

                    byte[] nonce;
                    byte[] tag;
                    try
                    {
                        nonce = Convert.FromBase64String(metadata.EncryptionNonce!);
                        tag = Convert.FromBase64String(metadata.EncryptionTag!);
                    }
                    catch (FormatException)
                    {
                        return Result<SodiumSecureMemoryHandle, FailureBase>.Err(
                            KeySplittingFailure.InvalidShareData(ErrorMessageInvalidEncryptionMetadata));
                    }
                    byte[] aad = BuildShareAad(accountId, record.ShareIndex, record.CredentialsVersion);

                    Result<byte[], FailureBase> decryptResult =
                        DecryptShareData(shareBytes, encryptionKey, nonce, tag, aad);
                    if (decryptResult.IsErr)
                    {
                        return Result<SodiumSecureMemoryHandle, FailureBase>.Err(decryptResult.UnwrapErr());
                    }

                    shareBytes = decryptResult.Unwrap();
                }

                KeyShare share = new(
                    shareData: shareBytes,
                    index: record.ShareIndex,
                    location: Enum.Parse<ShareLocation>(record.StorageLocation),
                    sessionId: metadata.SessionId
                );

                shares.Add(share);
            }

            if (hasHmac == true)
            {
                Result<SodiumSecureMemoryHandle, FailureBase> hmacHandleResult =
                    CreateHmacKeyHandle(credentials.MaskingKey);
                if (hmacHandleResult.IsErr)
                {
                    return Result<SodiumSecureMemoryHandle, FailureBase>.Err(hmacHandleResult.UnwrapErr());
                }

                hmacKeyHandle = hmacHandleResult.Unwrap();
            }

            Result<SodiumSecureMemoryHandle, KeySplittingFailure> reconstructResult =
                await secretSharingService.ReconstructKeyHandleAsync(
                    shares.ToArray(),
                    hmacKeyHandle: hasHmac == true ? hmacKeyHandle : null);

            if (reconstructResult.IsErr)
            {
                KeySplittingFailure error = reconstructResult.UnwrapErr();
                return Result<SodiumSecureMemoryHandle, FailureBase>.Err(error);
            }

            SodiumSecureMemoryHandle masterKeyHandle = reconstructResult.Unwrap();

            return Result<SodiumSecureMemoryHandle, FailureBase>.Ok(masterKeyHandle);
        }
        catch (Exception ex)
        {
            return Result<SodiumSecureMemoryHandle, FailureBase>.Err(
                KeySplittingFailure.KeyReconstructionFailed(ErrorMessageUnexpectedReconstructionError, ex));
        }
        finally
        {
            if (shares != null)
            {
                foreach (KeyShare share in shares)
                {
                    share.Dispose();
                }
            }

            hmacKeyHandle?.Dispose();

            if (encryptionKey != null)
            {
                CryptographicOperations.ZeroMemory(encryptionKey);
            }

            if (credentials != null)
            {
                CryptographicOperations.ZeroMemory(credentials.MaskingKey);
                CryptographicOperations.ZeroMemory(credentials.SecureKey);
            }
        }
    }

    private async Task<Result<InsertMasterKeySharesResult, KeySplittingFailure>> PersistSharesAsync(
        Guid accountId,
        KeySplitResult keySplitResult,
        int credentialsVersion,
        byte[] encryptionKey,
        bool hasHmac)
    {
        try
        {
            IActorRef masterKeySharePersistor = actorRegistry.Get(ActorIds.MasterKeySharePersistorActor);
            List<ShareData> shareDataList = new(keySplitResult.Shares.Length);

            foreach (KeyShare share in keySplitResult.Shares)
            {
                byte[] aad = BuildShareAad(accountId, share.ShareIndex, credentialsVersion);
                Result<EncryptedSharePayload, FailureBase> encryptResult =
                    EncryptShareData(share.ShareData, encryptionKey, aad);

                if (encryptResult.IsErr)
                {
                    FailureBase error = encryptResult.UnwrapErr();
                    return Result<InsertMasterKeySharesResult, KeySplittingFailure>.Err(
                        KeySplittingFailure.KeySplittingFailed($"{ErrorMessagePersistSharesFailed}: {error.Message}",
                            error.InnerException));
                }

                EncryptedSharePayload payload = encryptResult.Unwrap();

                ShareMetadata metadata = new()
                {
                    ShareId = Convert.ToBase64String(share.ShareId),
                    SessionId = share.SessionId,
                    CreatedAt = share.CreatedAt,
                    HasHmac = hasHmac,
                    EncryptionVersion = ShareEncryptionVersion,
                    EncryptionNonce = Convert.ToBase64String(payload.Nonce),
                    EncryptionTag = Convert.ToBase64String(payload.Tag)
                };

                string metadataJson = System.Text.Json.JsonSerializer.Serialize(metadata);
                shareDataList.Add(new ShareData(
                    share.ShareIndex,
                    payload.Ciphertext,
                    metadataJson,
                    share.Location.ToString()));
            }

            CreateMasterKeySharesCommand insertEvent = new(
                accountId,
                shareDataList
            );

            Result<InsertMasterKeySharesResult, MasterKeyFailure> result =
                await masterKeySharePersistor.Ask<Result<InsertMasterKeySharesResult, MasterKeyFailure>>(
                    insertEvent,
                    TimeSpan.FromSeconds(_askTimeoutSeconds));

            if (result.IsOk)
            {
                Log.Information(
                    "[MASTER-KEY-SHARES] Persisted {ShareCount} shares for account {AccountId}. CredentialsVersion={CredentialsVersion}, HasHmac={HasHmac}, EncryptionVersion={EncryptionVersion}",
                    shareDataList.Count,
                    accountId,
                    credentialsVersion,
                    hasHmac,
                    ShareEncryptionVersion);
            }

            return result.Match(
                Result<InsertMasterKeySharesResult, KeySplittingFailure>.Ok,
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

    private async Task<Result<MasterKeyShareQueryRecord[], KeySplittingFailure>> RetrieveSharesAsync(Guid accountId)
    {
        try
        {
            IActorRef masterKeySharePersistor = actorRegistry.Get(ActorIds.MasterKeySharePersistorActor);
            GetMasterKeySharesQuery getEvent = new(accountId);

            Result<MasterKeyShareQueryRecord[], MasterKeyFailure> result =
                await masterKeySharePersistor.Ask<Result<MasterKeyShareQueryRecord[], MasterKeyFailure>>(
                    getEvent,
                    TimeSpan.FromSeconds(_defaultTotalShares));

            return result.Match(
                ok => Result<MasterKeyShareQueryRecord[], KeySplittingFailure>.Ok(ok),
                err => err.Message.Contains(MasterKeyMessageKeys.SharesNotFound)
                    ? Result<MasterKeyShareQueryRecord[], KeySplittingFailure>.Ok(
                        Array.Empty<MasterKeyShareQueryRecord>())
                    : Result<MasterKeyShareQueryRecord[], KeySplittingFailure>.Err(
                        KeySplittingFailure.KeyReconstructionFailed(
                            $"{ErrorMessageRetrieveSharesFailed}: {err.Message}",
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

    private async Task<Result<Unit, KeySplittingFailure>> DeleteExistingSharesAsync(Guid accountId)
    {
        try
        {
            IActorRef masterKeySharePersistor = actorRegistry.Get(ActorIds.MasterKeySharePersistorActor);
            DeleteMasterKeySharesCommand deleteEvent = new(accountId);

            Result<Unit, MasterKeyFailure> result =
                await masterKeySharePersistor.Ask<Result<Unit, MasterKeyFailure>>(
                    deleteEvent,
                    TimeSpan.FromSeconds(_defaultTotalShares));

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

    private async Task<Result<CredentialsRecord, FailureBase>> GetCredentialsAsync(Guid accountId)
    {
        try
        {
            await using EcliptixSchemaContext schemaContext =
                await dbContextFactory.CreateDbContextAsync();

            Option<CredentialsRecord> credentialsOpt =
                await AccountSecureKeyAuthQueries.GetCredentialsForAccount(schemaContext, accountId);

            if (!credentialsOpt.IsSome)
            {
                return Result<CredentialsRecord, FailureBase>.Err(
                    KeySplittingFailure.InvalidIdentifier(ErrorMessageCredentialsMissing));
            }

            return Result<CredentialsRecord, FailureBase>.Ok(credentialsOpt.Value!);
        }
        catch (Exception ex)
        {
            return Result<CredentialsRecord, FailureBase>.Err(
                KeySplittingFailure.KeyDerivationFailed($"Failed to load credentials: {ex.Message}", ex));
        }
    }

    private static Result<Unit, FailureBase> ValidateMaskingKey(byte[] maskingKey)
    {
        return maskingKey.Length == MaskingKeyLength
            ? Result<Unit, FailureBase>.Ok(Unit.Value)
            : Result<Unit, FailureBase>.Err(
                KeySplittingFailure.InvalidKeyData($"Masking key must be {MaskingKeyLength} bytes"));
    }

    private static Result<SodiumSecureMemoryHandle, FailureBase> CreateHmacKeyHandle(byte[] maskingKey)
    {
        Result<Unit, FailureBase> validateResult = ValidateMaskingKey(maskingKey);
        if (validateResult.IsErr)
        {
            return Result<SodiumSecureMemoryHandle, FailureBase>.Err(validateResult.UnwrapErr());
        }

        Result<SodiumSecureMemoryHandle, SodiumFailure> allocateResult =
            SodiumSecureMemoryHandle.Allocate(maskingKey.Length);

        if (allocateResult.IsErr)
        {
            return Result<SodiumSecureMemoryHandle, FailureBase>.Err(
                KeySplittingFailure.HmacKeyStorageFailed(allocateResult.UnwrapErr().Message));
        }

        SodiumSecureMemoryHandle handle = allocateResult.Unwrap();
        Result<Unit, SodiumFailure> writeResult = handle.Write(maskingKey);
        if (writeResult.IsErr)
        {
            handle.Dispose();
            return Result<SodiumSecureMemoryHandle, FailureBase>.Err(
                KeySplittingFailure.HmacKeyStorageFailed(writeResult.UnwrapErr().Message));
        }

        return Result<SodiumSecureMemoryHandle, FailureBase>.Ok(handle);
    }

    private static byte[] DeriveShareEncryptionKey(byte[] maskingKey, Guid accountId)
    {
        byte[] encryptionKey = new byte[Constants.AesKeySize];

        Span<byte> salt = stackalloc byte[16];
        accountId.TryWriteBytes(salt);

        HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            ikm: maskingKey,
            output: encryptionKey,
            salt: salt,
            info: ShareEncryptionInfo);

        return encryptionKey;
    }

    private static byte[] BuildShareAad(Guid accountId, int shareIndex, int credentialsVersion)
    {
        byte[] aad = new byte[24];
        accountId.TryWriteBytes(aad.AsSpan(0, 16));
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(16, 4), shareIndex);
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(20, 4), credentialsVersion);
        return aad;
    }

    private static Result<EncryptedSharePayload, FailureBase> EncryptShareData(
        byte[] plaintext,
        byte[] encryptionKey,
        byte[] aad)
    {
        try
        {
            byte[] nonce = RandomNumberGenerator.GetBytes(Constants.AesGcmNonceSize);
            byte[] tag = new byte[Constants.AesGcmTagSize];
            byte[] ciphertext = new byte[plaintext.Length];

            using AesGcm aesGcm = new(encryptionKey, Constants.AesGcmTagSize);
            aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);

            return Result<EncryptedSharePayload, FailureBase>.Ok(
                new EncryptedSharePayload(ciphertext, nonce, tag));
        }
        catch (CryptographicException ex)
        {
            return Result<EncryptedSharePayload, FailureBase>.Err(
                KeySplittingFailure.KeySplittingFailed($"Share encryption failed: {ex.Message}", ex));
        }
    }

    private static Result<byte[], FailureBase> DecryptShareData(
        byte[] ciphertext,
        byte[] encryptionKey,
        byte[] nonce,
        byte[] tag,
        byte[] aad)
    {
        try
        {
            byte[] plaintext = new byte[ciphertext.Length];
            using AesGcm aesGcm = new(encryptionKey, Constants.AesGcmTagSize);
            aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, aad);
            return Result<byte[], FailureBase>.Ok(plaintext);
        }
        catch (CryptographicException ex)
        {
            return Result<byte[], FailureBase>.Err(
                KeySplittingFailure.KeyReconstructionFailed($"{ErrorMessageShareDecryptFailed}: {ex.Message}", ex));
        }
    }

    private readonly record struct EncryptedSharePayload(byte[] Ciphertext, byte[] Nonce, byte[] Tag);

    public async Task<Result<SodiumSecureMemoryHandle, FailureBase>> GetMasterKeyHandleAsync(Guid accountId)
    {
        try
        {
            Result<SodiumSecureMemoryHandle, FailureBase> reconstructResult =
                await ReconstructMasterKeyAsync(accountId);
            if (reconstructResult.IsErr)
            {
                FailureBase error = reconstructResult.UnwrapErr();
                return Result<SodiumSecureMemoryHandle, FailureBase>.Err(error);
            }

            SodiumSecureMemoryHandle masterKeyHandle = reconstructResult.Unwrap();

            return Result<SodiumSecureMemoryHandle, FailureBase>.Ok(masterKeyHandle);
        }
        catch (Exception ex)
        {
            return Result<SodiumSecureMemoryHandle, FailureBase>.Err(
                KeySplittingFailure.KeyReconstructionFailed(
                    $"Unexpected error retrieving master key handle: {ex.Message}", ex));
        }
    }
}
