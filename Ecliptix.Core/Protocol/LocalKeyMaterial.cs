using System.Security.Cryptography;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.PubKeyExchange;
using Sodium;

namespace Ecliptix.Core.Protocol;

public sealed class LocalKeyMaterial : IDisposable
{
    // Use SafeHandles for secret keys
    private SodiumSecureMemoryHandle _ed25519SecretKeyHandle;
    public readonly byte[] Ed25519PublicKey;

    private SodiumSecureMemoryHandle _identityX25519SecretKeyHandle;
    public readonly byte[] IdentityX25519PublicKey;

    public uint SignedPreKeyId { get; private set; }
    private SodiumSecureMemoryHandle _signedPreKeySecretKeyHandle;
    public readonly byte[] SignedPreKeyPublic;
    public readonly byte[] SignedPreKeySignature;

    private List<OneTimePreKeyLocal> _oneTimePreKeysInternal;
    public IReadOnlyList<OneTimePreKeyLocal> OneTimePreKeys => _oneTimePreKeysInternal.AsReadOnly();

    private SodiumSecureMemoryHandle? _ephemeralSecretKeyHandle;
    public byte[]? EphemeralX25519PublicKey { get; private set; }

    private bool _disposed;

    public LocalKeyMaterial(uint oneTimeKeyCount)
    {
        if (oneTimeKeyCount > int.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(oneTimeKeyCount), "Too many one-time keys requested.");

        SodiumCore.Init();

        SodiumSecureMemoryHandle? tempEdSkHandle = null;
        SodiumSecureMemoryHandle? tempIdSkHandle = null;
        SodiumSecureMemoryHandle? tempSpkSkHandle = null;
        List<OneTimePreKeyLocal>? tempOpks = null;
        byte[]? tempEdSkBytes = null;

        try
        {
            KeyPair edKeyPair = PublicKeyAuth.GenerateKeyPair();
            tempEdSkBytes = edKeyPair.PrivateKey;
            Ed25519PublicKey = edKeyPair.PublicKey;
            tempEdSkHandle = SodiumSecureMemoryHandle.Allocate(Constants.Ed25519SecretKeySize);
            tempEdSkHandle.Write(tempEdSkBytes);
            SodiumInterop.SecureWipe(tempEdSkBytes);
            tempEdSkBytes = null;

            // --- Identity Key Pair ---
            tempIdSkHandle = SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize);
            byte[] tempIdSkBytes = SodiumCore.GetRandomBytes(Constants.X25519PrivateKeySize);
            tempIdSkHandle.Write(tempIdSkBytes);
            SodiumInterop.SecureWipe(tempIdSkBytes);
            byte[] tempIdPrivCopy = new byte[Constants.X25519PrivateKeySize];
            tempIdSkHandle.Read(tempIdPrivCopy);
            IdentityX25519PublicKey = Sodium.ScalarMult.Base(tempIdPrivCopy);
            SodiumInterop.SecureWipe(tempIdPrivCopy);

            SignedPreKeyId = GenerateRandomUInt32();
            tempSpkSkHandle = SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize);
            byte[] tempSpkSkBytes = SodiumCore.GetRandomBytes(Constants.X25519PrivateKeySize);
            tempSpkSkHandle.Write(tempSpkSkBytes);
            SodiumInterop.SecureWipe(tempSpkSkBytes);
            byte[] tempSpkPrivCopy = new byte[Constants.X25519PrivateKeySize];
            tempSpkSkHandle.Read(tempSpkPrivCopy);
            SignedPreKeyPublic = Sodium.ScalarMult.Base(tempSpkPrivCopy);
            SodiumInterop.SecureWipe(tempSpkPrivCopy);

            byte[] tempEdSignKeyCopy = new byte[Constants.Ed25519SecretKeySize];
            tempEdSkHandle.Read(tempEdSignKeyCopy);
            SignedPreKeySignature = PublicKeyAuth.SignDetached(SignedPreKeyPublic, tempEdSignKeyCopy);
            SodiumInterop.SecureWipe(tempEdSignKeyCopy);

            int count = (int)oneTimeKeyCount;
            tempOpks = new List<OneTimePreKeyLocal>(count);
            HashSet<uint> usedIds = new HashSet<uint>(count);
            uint initialIdCounter = 2;

            for (int i = 0; i < count; i++)
            {
                uint id = initialIdCounter + (uint)i;
                while (usedIds.Contains(id)) id = GenerateRandomUInt32();
                usedIds.Add(id);

                Result<OneTimePreKeyLocal, ShieldError> opkResult = OneTimePreKeyLocal.Generate(id);
                if (opkResult.IsErr)
                {
                    ShieldError error = opkResult.UnwrapErr();
                    throw new CryptographicException($"Failed to generate one-time prekey with ID {id}: {error}",
                        error.InnerException);
                }

                tempOpks.Add(opkResult.Unwrap());
            }

            _ed25519SecretKeyHandle = tempEdSkHandle;
            _identityX25519SecretKeyHandle = tempIdSkHandle;
            _signedPreKeySecretKeyHandle = tempSpkSkHandle;
            _oneTimePreKeysInternal = tempOpks;

            tempEdSkHandle = null;
            tempIdSkHandle = null;
            tempSpkSkHandle = null;
            tempOpks = null;
        }
        catch (Exception ex)
        {
            tempEdSkHandle?.Dispose();
            tempIdSkHandle?.Dispose();
            tempSpkSkHandle?.Dispose();
            if (tempEdSkBytes != null) SodiumInterop.SecureWipe(tempEdSkBytes);
            if (tempOpks != null)
            {
                foreach (OneTimePreKeyLocal opk in tempOpks) opk.Dispose();
            }

            throw new CryptographicException($"Failed to initialize LocalKeyMaterial: {ex.Message}", ex);
        }
    }

    private static uint GenerateRandomUInt32()
    {
        byte[] buffer = SodiumCore.GetRandomBytes(sizeof(uint)); // Temporary buffer is fine here
        return BitConverter.ToUInt32(buffer, 0);
    }

    private void SecureCleanupLogic()
    {
        _ed25519SecretKeyHandle?.Dispose();
        _identityX25519SecretKeyHandle?.Dispose();
        _signedPreKeySecretKeyHandle?.Dispose();
        _ephemeralSecretKeyHandle?.Dispose();

        foreach (OneTimePreKeyLocal opk in _oneTimePreKeysInternal)
        {
            opk.Dispose();
        }

        _oneTimePreKeysInternal.Clear();

        _ed25519SecretKeyHandle = null!;
        _identityX25519SecretKeyHandle = null!;
        _signedPreKeySecretKeyHandle = null!;
        _oneTimePreKeysInternal = null!;
        _ephemeralSecretKeyHandle = null;
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                // Dispose managed state (SafeHandles and List)
                SecureCleanupLogic();
            }

            // No unmanaged resources directly owned by this class (SafeHandles own them).
            // Finalizer remains as a *fallback* for the SafeHandles if Dispose isn't called,
            // but explicit Dispose is highly preferred.
            _disposed = true;
        }
    }

    // Finalizer for fallback safety net provided by SafeHandles
    ~LocalKeyMaterial()
    {
        Dispose(false);
    }

    public LocalPublicKeyBundle CreatePublicBundle(byte[]? ephemeralPublicKey = null)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(LocalKeyMaterial));

        // Validate optional ephemeral key size if provided
        if (ephemeralPublicKey != null && ephemeralPublicKey.Length != Constants.X25519PublicKeySize)
            throw new ArgumentException($"Ephemeral key must be {Constants.X25519PublicKeySize} bytes.",
                nameof(ephemeralPublicKey));

        // Convert OneTimePreKeyLocal list to OneTimePreKeyRecord list
        // Note: OneTimePreKeyRecord now uses record equality.
        List<OneTimePreKeyRecord> opkRecords = _oneTimePreKeysInternal
            .Select(opkLocal => new OneTimePreKeyRecord(opkLocal.PreKeyId, opkLocal.PublicKey))
            .ToList(); // Create a new list of the public records

        // Create and populate the LocalPublicKeyBundle record
        // using public properties of this instance
        LocalPublicKeyBundle bundle = new(
            IdentityEd25519: this.Ed25519PublicKey,
            IdentityX25519: this.IdentityX25519PublicKey,
            SignedPreKeyId: this.SignedPreKeyId,
            SignedPreKeyPublic: this.SignedPreKeyPublic,
            SignedPreKeySignature: this.SignedPreKeySignature,
            OneTimePreKeys: opkRecords, // Pass the list of public records
            EphemeralX25519: ephemeralPublicKey // Assign the nullable parameter directly
        );

        return bundle;
    }

    public Result<SodiumSecureMemoryHandle, ShieldFailure> X3dhDeriveSharedSecret(
        LocalPublicKeyBundle remoteBundle, // Bob's Bundle
        ReadOnlySpan<byte> info,
        ILogger? logger = null) // Optional logger
    {
        logger?.LogDebug("Initiating X3DH derivation (Alice's perspective).");
        if (_disposed)
            throw new ObjectDisposedException(nameof(LocalKeyMaterial));
        if (info.IsEmpty)
            return Result<SodiumSecureMemoryHandle, ShieldFailure>.Err(
                ShieldFailure.DeriveKeyFailed("HKDF info parameter cannot be empty."));
        if (_ephemeralSecretKeyHandle == null || _ephemeralSecretKeyHandle.IsInvalid)
            throw new InvalidOperationException("Local ephemeral key is invalid. Call GenerateEphemeralKeyPair first.");
        if (_identityX25519SecretKeyHandle == null || _identityX25519SecretKeyHandle.IsInvalid)
            throw new InvalidOperationException("Local identity key is invalid.");
        if (remoteBundle == null)
            return Result<SodiumSecureMemoryHandle, ShieldFailure>.Err(
                ShieldFailure.InvalidInput("Remote bundle cannot be null.")); // Added null check

        // Validate necessary keys in remote bundle
        if (remoteBundle.IdentityX25519 == null || remoteBundle.IdentityX25519.Length != Constants.X25519PublicKeySize)
            return Result<SodiumSecureMemoryHandle, ShieldFailure>.Err(
                ShieldFailure.PeerPubKeyFailed("Invalid remote X25519 identity public key in bundle."));
        if (remoteBundle.SignedPreKeyPublic == null ||
            remoteBundle.SignedPreKeyPublic.Length != Constants.X25519PublicKeySize)
            return Result<SodiumSecureMemoryHandle, ShieldFailure>.Err(
                ShieldFailure.PeerPubKeyFailed("Invalid remote signed prekey public key in bundle."));


        // Allocate temporary managed buffers for secrets (must be wiped!)
        byte[]? ephemeralSecretCopy = null;
        byte[]? identitySecretCopy = null;
        byte[]? dh1 = null; // DH(E_a, IK_b)
        byte[]? dh2 = null; // DH(E_a, SPK_b)
        byte[]? dh3 = null; // DH(IK_a, SPK_b)
        byte[]? dh4 = null; // DH(E_a, OPK_b) - Optional
        byte[]? dhConcatBytes = null;
        byte[]? hkdfOutput = null;
        SodiumSecureMemoryHandle? secureOutputHandle = null;

        try
        {
            logger?.LogTrace("Copying local secrets for DH.");
            ephemeralSecretCopy = new byte[Constants.X25519PrivateKeySize];
            _ephemeralSecretKeyHandle.Read(ephemeralSecretCopy);

            identitySecretCopy = new byte[Constants.X25519PrivateKeySize];
            _identityX25519SecretKeyHandle.Read(identitySecretCopy);

            // --- Perform DH Calculations (Alice's Perspective) ---
            logger?.LogTrace("Performing DH calculations.");
            // DH1 = DH(E_a, IK_b)
            dh1 = Sodium.ScalarMult.Mult(ephemeralSecretCopy, remoteBundle.IdentityX25519);
            // DH2 = DH(E_a, SPK_b)
            dh2 = Sodium.ScalarMult.Mult(ephemeralSecretCopy, remoteBundle.SignedPreKeyPublic);
            // DH3 = DH(IK_a, SPK_b)
            dh3 = Sodium.ScalarMult.Mult(identitySecretCopy, remoteBundle.SignedPreKeyPublic);

            // DH4 = DH(E_a, OPK_b) (Optional)
            // Alice uses the OPK provided in the bundle (should be at most one)
            var remoteOpk = remoteBundle.OneTimePreKeys.FirstOrDefault();
            if (remoteOpk != null)
            {
                logger?.LogTrace("Remote OPK found (ID: {OpkId}), calculating DH4.", remoteOpk.PreKeyId);
                if (remoteOpk.PublicKey is { Length: Constants.X25519PublicKeySize })
                {
                    dh4 = Sodium.ScalarMult.Mult(ephemeralSecretCopy, remoteOpk.PublicKey);
                }
                else
                {
                    logger?.LogWarning(
                        "Remote one-time prekey (ID: {OpkId}) has invalid length ({Length}), skipping DH4.",
                        remoteOpk.PreKeyId, remoteOpk.PublicKey?.Length ?? -1);
                    // Depending on protocol strictness, you might return an error here:
                    // return Result<SodiumSecureMemoryHandle, ShieldFailure>.Err(ShieldFailure.PeerPubKeyFailed($"Invalid remote one-time prekey (ID: {remoteOpk.PreKeyId}) public key length."));
                }
            }
            else
            {
                logger?.LogTrace("No remote OPK found in bundle, skipping DH4.");
            }

            // --- Wipe temporary secret key copies NOW ---
            logger?.LogTrace("Wiping temporary secret copies.");
            SodiumInterop.SecureWipe(ephemeralSecretCopy);
            ephemeralSecretCopy = null;
            SodiumInterop.SecureWipe(identitySecretCopy);
            identitySecretCopy = null;

            // --- Concatenate DH results ---
            logger?.LogTrace("Concatenating DH results.");
            int totalDhLength = dh1.Length + dh2.Length + dh3.Length + (dh4?.Length ?? 0);
            dhConcatBytes = new byte[totalDhLength];
            int currentOffset = 0;
            Buffer.BlockCopy(dh1, 0, dhConcatBytes, currentOffset, dh1.Length);
            currentOffset += dh1.Length;
            Buffer.BlockCopy(dh2, 0, dhConcatBytes, currentOffset, dh2.Length);
            currentOffset += dh2.Length;
            Buffer.BlockCopy(dh3, 0, dhConcatBytes, currentOffset, dh3.Length);
            currentOffset += dh3.Length;
            if (dh4 != null)
            {
                Buffer.BlockCopy(dh4, 0, dhConcatBytes, currentOffset, dh4.Length);
            }

            // --- HKDF-Expand ---
            logger?.LogTrace("Performing HKDF expansion.");
            hkdfOutput = new byte[Constants.X25519KeySize];
            byte[] hkdfSalt = new byte[32]; // Use default zero salt explicitly
            try
            {
                using (var hkdf = new HkdfSha256(dhConcatBytes, hkdfSalt)) // Pass IKM and Salt
                {
                    hkdf.Expand(info, hkdfOutput);
                }
            }
            finally
            {
                SodiumInterop.SecureWipe(hkdfSalt); // Wipe explicit salt
            }

            // --- Store result in secure memory ---
            logger?.LogTrace("Allocating secure handle for final secret.");
            secureOutputHandle = SodiumSecureMemoryHandle.Allocate(hkdfOutput.Length);
            secureOutputHandle.Write(hkdfOutput);

            logger?.LogInformation("Derived X3DH shared secret successfully (Alice).");

            // Return the handle holding the securely stored secret
            return Result<SodiumSecureMemoryHandle, ShieldFailure>.Ok(secureOutputHandle);
        }
        catch (Exception ex)
        {
            // Dispose output handle if partially created
            secureOutputHandle?.Dispose();
            logger?.LogError(ex, "Failed during X3DH shared secret derivation (Alice).");
            return Result<SodiumSecureMemoryHandle, ShieldFailure>.Err(
                ShieldFailure.DeriveKeyFailed($"Internal error during secret derivation (Alice): {ex.Message}")
            );
        }
        finally
        {
            // Final Cleanup: Ensure ALL temporary buffers are wiped
            logger?.LogTrace("Performing final cleanup (Alice).");
            if (ephemeralSecretCopy != null) SodiumInterop.SecureWipe(ephemeralSecretCopy);
            if (identitySecretCopy != null) SodiumInterop.SecureWipe(identitySecretCopy);
            if (dh1 != null) SodiumInterop.SecureWipe(dh1);
            if (dh2 != null) SodiumInterop.SecureWipe(dh2);
            if (dh3 != null) SodiumInterop.SecureWipe(dh3);
            if (dh4 != null) SodiumInterop.SecureWipe(dh4);
            if (dhConcatBytes != null) SodiumInterop.SecureWipe(dhConcatBytes);
            if (hkdfOutput != null) SodiumInterop.SecureWipe(hkdfOutput);
        }
    }

    public static Result<bool, ShieldFailure> VerifyRemoteSpkSignature(
        ReadOnlySpan<byte> remoteIdentityEd25519,
        ReadOnlySpan<byte> remoteSpkPublic,
        ReadOnlySpan<byte> remoteSpkSignature)
    {
        if (remoteIdentityEd25519.Length != Constants.Ed25519PublicKeySize)
        {
            string msg =
                $"Invalid remote Ed25519 identity key length: expected {Constants.Ed25519PublicKeySize}, got {remoteIdentityEd25519.Length}.";
            return Result<bool, ShieldFailure>.Err(ShieldFailure.PeerPubKeyFailed(msg));
        }

        if (remoteSpkPublic.Length != Constants.X25519PublicKeySize) // Message is X25519 key
        {
            string msg =
                $"Invalid remote Signed PreKey public key length: expected {Constants.X25519PublicKeySize}, got {remoteSpkPublic.Length}.";
            return Result<bool, ShieldFailure>.Err(ShieldFailure.HandshakeFailed(msg));
        }

        if (remoteSpkSignature.Length != Constants.Ed25519SignatureSize)
        {
            string msg =
                $"Invalid remote Signed PreKey signature length: expected {Constants.Ed25519SignatureSize}, got {remoteSpkSignature.Length}.";
            return Result<bool, ShieldFailure>.Err(ShieldFailure.HandshakeFailed(msg));
        }

        try
        {
            bool isValid = Sodium.PublicKeyAuth.VerifyDetached(
                remoteSpkSignature.ToArray(),
                remoteSpkPublic.ToArray(),
                remoteIdentityEd25519.ToArray());
            return Result<bool, ShieldFailure>.Ok(isValid);
        }
        catch (Exception ex)
        {
            return Result<bool, ShieldFailure>.Err(
                ShieldFailure.HandshakeFailed($"Internal error during signature verification: {ex.Message}")
            );
        }
    }

    public byte[] GenerateEphemeralKeyPair()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(LocalKeyMaterial));

        // Dispose existing ephemeral key handle if it exists
        _ephemeralSecretKeyHandle?.Dispose();
        _ephemeralSecretKeyHandle = null;
        EphemeralX25519PublicKey = null;

        SodiumSecureMemoryHandle? tempEphemeralHandle = null;
        byte[]? tempPrivateKeyBytes = null;
        byte[]? publicKey = null;

        try
        {
            // Allocate secure memory
            tempEphemeralHandle = SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize);

            // Generate random bytes into temporary managed buffer
            tempPrivateKeyBytes = SodiumCore.GetRandomBytes(Constants.X25519PrivateKeySize);

            // Copy temporary bytes into secure memory
            tempEphemeralHandle.Write(tempPrivateKeyBytes);

            // Wipe temporary buffer
            SodiumInterop.SecureWipe(tempPrivateKeyBytes);
            tempPrivateKeyBytes = null;

            // Generate public key using data from secure memory handle
            byte[] tempPrivKeyCopy = new byte[Constants.X25519PrivateKeySize];
            tempEphemeralHandle.Read(tempPrivKeyCopy); // Copy out
            publicKey = ScalarMult.Base(tempPrivKeyCopy); // Use the copy
            SodiumInterop.SecureWipe(tempPrivKeyCopy); // Wipe the temporary copy

            // Store the new handle and public key
            _ephemeralSecretKeyHandle = tempEphemeralHandle;
            EphemeralX25519PublicKey = publicKey;

            // Nullify temp handle so catch block doesn't double-dispose if successful
            tempEphemeralHandle = null;

            return publicKey;
        }
        catch (Exception ex)
        {
            // Clean up if generation failed
            tempEphemeralHandle?.Dispose(); // Dispose handle if partially created
            if (tempPrivateKeyBytes != null) SodiumInterop.SecureWipe(tempPrivateKeyBytes); // Ensure temp wipe

            // Reset internal state
            _ephemeralSecretKeyHandle = null;
            EphemeralX25519PublicKey = null;

            throw new CryptographicException("Failed to generate ephemeral key pair.", ex);
        }
    }

    public Result<SodiumSecureMemoryHandle, ShieldFailure> CalculateSharedSecretAsRecipient(
        ReadOnlySpan<byte> remoteIdentityPublicKeyX, // Alice's X25519 ID Key
        ReadOnlySpan<byte> remoteEphemeralPublicKeyX, // Alice's Ephemeral Key
        uint? usedLocalOpkId, // ID of Bob's OPK used by Alice (null if none)
        ReadOnlySpan<byte> info,
        ILogger? logger = null) // Optional logger
    {
        logger?.LogDebug("Initiating X3DH derivation (Bob's perspective).");
        if (_disposed)
            throw new ObjectDisposedException(nameof(LocalKeyMaterial));
        if (info.IsEmpty)
            return Result<SodiumSecureMemoryHandle, ShieldFailure>.Err(
                ShieldFailure.DeriveKeyFailed("HKDF info parameter cannot be empty."));

        // Validate Alice's provided public keys
        if (remoteIdentityPublicKeyX.Length != Constants.X25519PublicKeySize)
            return Result<SodiumSecureMemoryHandle, ShieldFailure>.Err(
                ShieldFailure.PeerPubKeyFailed("Invalid remote X25519 identity public key length."));
        if (remoteEphemeralPublicKeyX.Length != Constants.X25519PublicKeySize)
            return Result<SodiumSecureMemoryHandle, ShieldFailure>.Err(
                ShieldFailure.PeerPubKeyFailed("Invalid remote ephemeral public key length."));

        // Check local keys needed
        if (_identityX25519SecretKeyHandle == null || _identityX25519SecretKeyHandle.IsInvalid)
            throw new InvalidOperationException("Local identity key is invalid.");
        if (_signedPreKeySecretKeyHandle == null || _signedPreKeySecretKeyHandle.IsInvalid)
            throw new InvalidOperationException("Local signed prekey is invalid.");

        // Find the specific local One-Time PreKey handle *if* an ID was provided
        OneTimePreKeyLocal? usedOpk = null;
        SodiumSecureMemoryHandle? opkSecretHandle = null; // Store the handle directly
        if (usedLocalOpkId.HasValue)
        {
            logger?.LogTrace("Looking for local OPK with ID: {OpkId}", usedLocalOpkId.Value);
            // Find by ID. Use .Value to access struct fields if OneTimePreKeyLocal is struct
            usedOpk = _oneTimePreKeysInternal?.FirstOrDefault(opk => opk.PreKeyId == usedLocalOpkId.Value);

            if (usedOpk == null || usedOpk.Value.PrivateKeyHandle == null || usedOpk.Value.PrivateKeyHandle.IsInvalid)
            {
                logger?.LogWarning("Local OPK with ID {OpkId} not found or invalid.", usedLocalOpkId.Value);
                return Result<SodiumSecureMemoryHandle, ShieldFailure>.Err(
                    ShieldFailure.HandshakeFailed(
                        $"Local one-time prekey with ID {usedLocalOpkId.Value} not found or invalid."));
            }

            opkSecretHandle = usedOpk.Value.PrivateKeyHandle; // Get the handle
            logger?.LogTrace("Found local OPK with ID: {OpkId}", usedLocalOpkId.Value);
        }
        else
        {
            logger?.LogTrace("No local OPK ID provided by initiator.");
        }


        // Allocate temporary managed buffers for secrets (must be wiped!)
        byte[]? identitySecretCopy = null;
        byte[]? signedPreKeySecretCopy = null;
        byte[]? oneTimePreKeySecretCopy = null; // Only allocated if opkSecretHandle is not null
        byte[]? dh1 = null; // DH(IK_b, E_a) -> Alice DH1
        byte[]? dh2 = null; // DH(SPK_b, E_a) -> Alice DH2
        byte[]? dh3 = null; // DH(SPK_b, IK_a) -> Alice DH3
        byte[]? dh4 = null; // DH(OPK_b, E_a) -> Alice DH4 (optional)
        byte[]? dhConcatBytes = null;
        byte[]? hkdfOutput = null;
        SodiumSecureMemoryHandle? secureOutputHandle = null;

        try
        {
            logger?.LogTrace("Copying local secrets for DH.");
            identitySecretCopy = new byte[Constants.X25519PrivateKeySize];
            _identityX25519SecretKeyHandle.Read(identitySecretCopy);

            signedPreKeySecretCopy = new byte[Constants.X25519PrivateKeySize];
            _signedPreKeySecretKeyHandle.Read(signedPreKeySecretCopy);

            // Read OPK secret *only if* one was used
            if (opkSecretHandle != null)
            {
                oneTimePreKeySecretCopy = new byte[Constants.X25519PrivateKeySize];
                opkSecretHandle.Read(oneTimePreKeySecretCopy);
            }

            // --- Perform DH Calculations (Recipient's Perspective, matching Alice's IKM order) ---
            logger?.LogTrace("Performing DH calculations.");
            // Corresponds to Alice's DH1 (DH(Ea, IKb)) = DH(IKb, Ea)
            dh1 = Sodium.ScalarMult.Mult(identitySecretCopy, remoteEphemeralPublicKeyX.ToArray());

            // Corresponds to Alice's DH2 (DH(Ea, SPKb)) = DH(SPKb, Ea)
            dh2 = Sodium.ScalarMult.Mult(signedPreKeySecretCopy, remoteEphemeralPublicKeyX.ToArray());

            // Corresponds to Alice's DH3 (DH(IKa, SPKb)) = DH(SPKb, IKa)
            dh3 = Sodium.ScalarMult.Mult(signedPreKeySecretCopy, remoteIdentityPublicKeyX.ToArray());

            // Corresponds to Alice's DH4 (DH(Ea, OPKb)) = DH(OPKb, Ea) (Optional)
            if (oneTimePreKeySecretCopy != null) // Only calculate if OPK was used
            {
                logger?.LogTrace("Calculating DH4 using local OPK ID {OpkId}.", usedLocalOpkId);
                dh4 = Sodium.ScalarMult.Mult(oneTimePreKeySecretCopy, remoteEphemeralPublicKeyX.ToArray());
            }
            else
            {
                logger?.LogTrace("Skipping DH4 as no local OPK was specified.");
            }

            // --- Wipe temporary secret key copies NOW ---
            logger?.LogTrace("Wiping temporary secret copies.");
            SodiumInterop.SecureWipe(identitySecretCopy);
            identitySecretCopy = null;
            SodiumInterop.SecureWipe(signedPreKeySecretCopy);
            signedPreKeySecretCopy = null;
            if (oneTimePreKeySecretCopy != null) SodiumInterop.SecureWipe(oneTimePreKeySecretCopy);
            oneTimePreKeySecretCopy = null;

            // --- Concatenate DH results (Order must match Alice's concatenation!) ---
            logger?.LogTrace("Concatenating DH results.");
            int totalDhLength =
                dh1.Length + dh2.Length + dh3.Length + (dh4?.Length ?? 0); // Include dh4 only if calculated
            dhConcatBytes = new byte[totalDhLength];
            int currentOffset = 0;
            Buffer.BlockCopy(dh1, 0, dhConcatBytes, currentOffset, dh1.Length);
            currentOffset += dh1.Length;
            Buffer.BlockCopy(dh2, 0, dhConcatBytes, currentOffset, dh2.Length);
            currentOffset += dh2.Length;
            Buffer.BlockCopy(dh3, 0, dhConcatBytes, currentOffset, dh3.Length);
            currentOffset += dh3.Length;
            if (dh4 != null) // Only copy if dh4 exists
            {
                Buffer.BlockCopy(dh4, 0, dhConcatBytes, currentOffset, dh4.Length);
            }

            // --- HKDF-Expand ---
            logger?.LogTrace("Performing HKDF expansion.");
            hkdfOutput = new byte[Constants.X25519KeySize];
            byte[] hkdfSalt = new byte[32]; // Use default zero salt explicitly
            try
            {
                using (var hkdf = new HkdfSha256(dhConcatBytes, hkdfSalt))
                {
                    hkdf.Expand(info, hkdfOutput);
                }
            }
            finally
            {
                SodiumInterop.SecureWipe(hkdfSalt); // Wipe explicit salt
            }

            // --- Store result in secure memory ---
            logger?.LogTrace("Allocating secure handle for final secret.");
            secureOutputHandle = SodiumSecureMemoryHandle.Allocate(hkdfOutput.Length);
            secureOutputHandle.Write(hkdfOutput);

            logger?.LogInformation("Derived X3DH shared secret successfully as recipient using OPK ID: {OpkId}",
                usedLocalOpkId.HasValue ? usedLocalOpkId.Value.ToString() : "None");

            // Return the handle holding the securely stored secret
            return Result<SodiumSecureMemoryHandle, ShieldFailure>.Ok(secureOutputHandle);
        }
        catch (Exception ex)
        {
            secureOutputHandle?.Dispose();
            logger?.LogError(ex, "Failed during X3DH shared secret derivation as recipient.");
            return Result<SodiumSecureMemoryHandle, ShieldFailure>.Err(
                ShieldFailure.DeriveKeyFailed($"Internal error during secret derivation as recipient: {ex.Message}")
            );
        }
        finally
        {
            // Final Cleanup
            logger?.LogTrace("Performing final cleanup (Bob).");
            if (identitySecretCopy != null) SodiumInterop.SecureWipe(identitySecretCopy);
            if (signedPreKeySecretCopy != null) SodiumInterop.SecureWipe(signedPreKeySecretCopy);
            if (oneTimePreKeySecretCopy != null) SodiumInterop.SecureWipe(oneTimePreKeySecretCopy);
            if (dh1 != null) SodiumInterop.SecureWipe(dh1);
            if (dh2 != null) SodiumInterop.SecureWipe(dh2);
            if (dh3 != null) SodiumInterop.SecureWipe(dh3);
            if (dh4 != null) SodiumInterop.SecureWipe(dh4);
            if (dhConcatBytes != null) SodiumInterop.SecureWipe(dhConcatBytes);
            if (hkdfOutput != null) SodiumInterop.SecureWipe(hkdfOutput);
        }
    }
}