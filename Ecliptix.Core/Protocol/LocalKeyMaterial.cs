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
    //public IReadOnlyList<OneTimePreKeyLocal> OneTimePreKeys => _oneTimePreKeysInternal.AsReadOnly();

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
        byte[] buffer = SodiumCore.GetRandomBytes(sizeof(uint));
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

    public LocalPublicKeyBundle CreatePublicBundle()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        List<OneTimePreKeyRecord> opkRecords = _oneTimePreKeysInternal
            .Select(opkLocal => new OneTimePreKeyRecord(opkLocal.PreKeyId, opkLocal.PublicKey))
            .ToList();

        LocalPublicKeyBundle bundle = new(
            IdentityEd25519: this.Ed25519PublicKey,
            IdentityX25519: this.IdentityX25519PublicKey, // Corrected name assumed
            SignedPreKeyId: this.SignedPreKeyId,
            SignedPreKeyPublic: this.SignedPreKeyPublic,
            SignedPreKeySignature: this.SignedPreKeySignature,
            OneTimePreKeys: opkRecords,
            EphemeralX25519: EphemeralX25519PublicKey // Use field directly
        );

        return bundle;
    }

    public Result<SodiumSecureMemoryHandle, ShieldFailure> X3dhDeriveSharedSecret(
        LocalPublicKeyBundle remoteBundle, // Bob's Bundle (Internal C# Record)
        ReadOnlySpan<byte> info)
    {
        // ... (Checks for disposed, info, handles, remoteBundle keys remain) ...
        if (_disposed) throw new ObjectDisposedException(nameof(LocalKeyMaterial));
        if (info.IsEmpty)
            return Result<SodiumSecureMemoryHandle, ShieldFailure>.Err(
                ShieldFailure.DeriveKeyFailed("HKDF info empty."));
        if (_ephemeralSecretKeyHandle == null || _ephemeralSecretKeyHandle.IsInvalid)
            throw new InvalidOperationException("Local ephemeral key invalid.");
        if (_identityX25519SecretKeyHandle == null || _identityX25519SecretKeyHandle.IsInvalid)
            throw new InvalidOperationException("Local identity key invalid.");
        if (remoteBundle == null)
            return Result<SodiumSecureMemoryHandle, ShieldFailure>.Err(
                ShieldFailure.InvalidInput("Remote bundle null."));
        if (remoteBundle.IdentityX25519 is not { Length: Constants.X25519PublicKeySize })
            return Result<SodiumSecureMemoryHandle, ShieldFailure>.Err(
                ShieldFailure.PeerPubKeyFailed("Invalid remote IK."));
        if (remoteBundle.SignedPreKeyPublic is not { Length: Constants.X25519PublicKeySize })
            return Result<SodiumSecureMemoryHandle, ShieldFailure>.Err(
                ShieldFailure.PeerPubKeyFailed("Invalid remote SPK."));


        byte[]? ephemeralSecretCopy = null;
        byte[]? identitySecretCopy = null;
        byte[]? dh1 = null;
        byte[]? dh2 = null;
        byte[]? dh3 = null;
        byte[]? dh4 = null;
        byte[]? dhConcatBytes = null;
        byte[]? hkdfOutput = null;
        SodiumSecureMemoryHandle? secureOutputHandle = null;
        SodiumSecureMemoryHandle? ephemeralHandleToDispose = null; // Track handle used

        try
        {
            ephemeralSecretCopy = new byte[Constants.X25519PrivateKeySize];
            _ephemeralSecretKeyHandle.Read(ephemeralSecretCopy); // Read from internal handle
            ephemeralHandleToDispose = _ephemeralSecretKeyHandle; // Keep track to dispose later
            _ephemeralSecretKeyHandle = null; // Clear internal field *after* reading and tracking

            identitySecretCopy = new byte[Constants.X25519PrivateKeySize];
            _identityX25519SecretKeyHandle.Read(identitySecretCopy);

            // DH Calculations
            dh1 = ScalarMult.Mult(ephemeralSecretCopy, remoteBundle.IdentityX25519); // Alice Eph Priv, Bob ID Pub
            dh2 = ScalarMult.Mult(ephemeralSecretCopy, remoteBundle.SignedPreKeyPublic); // Alice Eph Priv, Bob SPK Pub
            dh3 = ScalarMult.Mult(identitySecretCopy, remoteBundle.SignedPreKeyPublic); // Alice ID Priv, Bob SPK Pub

            OneTimePreKeyRecord? remoteOpk = remoteBundle.OneTimePreKeys.FirstOrDefault();
            if (remoteOpk?.PublicKey is { Length: Constants.X25519PublicKeySize })
            {
                dh4 = ScalarMult.Mult(ephemeralSecretCopy, remoteOpk.PublicKey); // Alice Eph Priv, Bob OPK Pub
            }

            // *** ADDED LOGGING ***
            Console.WriteLine($"--- Alice Derivation ---");
            Console.WriteLine($"Alice DH1 (Ea, IKb): {Convert.ToHexString(dh1)}");
            Console.WriteLine($"Alice DH2 (Ea, SPKb): {Convert.ToHexString(dh2)}");
            Console.WriteLine($"Alice DH3 (IKa, SPKb): {Convert.ToHexString(dh3)}");
            if (dh4 != null) Console.WriteLine($"Alice DH4 (Ea, OPKb): {Convert.ToHexString(dh4)}");
            else Console.WriteLine("Alice DH4: null");
            // *** END LOGGING ***

            // Wipe temp secrets immediately after use
            SodiumInterop.SecureWipe(ephemeralSecretCopy);
            ephemeralSecretCopy = null;
            SodiumInterop.SecureWipe(identitySecretCopy);
            identitySecretCopy = null;

            // Concatenate
            int totalDhLength = dh1.Length + dh2.Length + dh3.Length + (dh4?.Length ?? 0);
            dhConcatBytes = new byte[totalDhLength];
            int currentOffset = 0;
            Buffer.BlockCopy(dh1, 0, dhConcatBytes, currentOffset, dh1.Length);
            currentOffset += dh1.Length; // DH1
            Buffer.BlockCopy(dh2, 0, dhConcatBytes, currentOffset, dh2.Length);
            currentOffset += dh2.Length; // DH2
            Buffer.BlockCopy(dh3, 0, dhConcatBytes, currentOffset, dh3.Length);
            currentOffset += dh3.Length; // DH3
            if (dh4 != null)
            {
                Buffer.BlockCopy(dh4, 0, dhConcatBytes, currentOffset, dh4.Length);
            } // DH4

            // *** ADDED LOGGING ***
            Console.WriteLine($"Alice IKM (Concat): {Convert.ToHexString(dhConcatBytes)}");
            // *** END LOGGING ***

            // HKDF
            hkdfOutput = new byte[Constants.X25519KeySize];
            // Use stackalloc for salt for efficiency and auto-cleanup (no need for finally wipe)
            Span<byte> hkdfSaltSpan = stackalloc byte[Constants.X25519KeySize]; // Zero salt
            // Note: HkdfSha256 constructor needs ReadOnlySpan<byte> for salt if using stackalloc
            using (HkdfSha256 hkdf = new(dhConcatBytes, hkdfSaltSpan)) // Pass Span for salt
            {
                hkdf.Expand(info, hkdfOutput); // Expand into heap buffer
            }
            // Salt span goes out of scope and is cleared

            // *** ADDED LOGGING ***
            Console.WriteLine($"Alice Final Secret (Output): {Convert.ToHexString(hkdfOutput)}");
            // *** END LOGGING ***

            secureOutputHandle = SodiumSecureMemoryHandle.Allocate(hkdfOutput.Length);
            secureOutputHandle.Write(hkdfOutput);

            var returnHandle = secureOutputHandle;
            secureOutputHandle = null; // Transfer ownership
            return Result<SodiumSecureMemoryHandle, ShieldFailure>.Ok(returnHandle);
        }
        catch (Exception ex)
        {
            secureOutputHandle?.Dispose();
            return Result<SodiumSecureMemoryHandle, ShieldFailure>.Err(
                ShieldFailure.DeriveKeyFailed($"Internal error (Alice): {ex.Message}"));
        } // Added inner ex
        finally
        {
            // Dispose ephemeral handle AFTER everything else
            ephemeralHandleToDispose?.Dispose();
            // Wipe heap buffers if not nulled out on success/error paths
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

    public void GenerateEphemeralKeyPair() 
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        _ephemeralSecretKeyHandle?.Dispose();
        _ephemeralSecretKeyHandle = null;
        if(EphemeralX25519PublicKey != null) SodiumInterop.SecureWipe(EphemeralX25519PublicKey);
        EphemeralX25519PublicKey = null;

        SodiumSecureMemoryHandle? tempEphemeralHandle = null;
        byte[]? tempPrivateKeyBytes = null;
        byte[]? publicKey = null; 

        try
        {
            tempEphemeralHandle = SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize);
            tempPrivateKeyBytes = SodiumCore.GetRandomBytes(Constants.X25519PrivateKeySize);
            tempEphemeralHandle.Write(tempPrivateKeyBytes);

            publicKey = ScalarMult.Base(tempPrivateKeyBytes);

            SodiumInterop.SecureWipe(tempPrivateKeyBytes);
            tempPrivateKeyBytes = null;

            _ephemeralSecretKeyHandle = tempEphemeralHandle;
            EphemeralX25519PublicKey = publicKey;

            tempEphemeralHandle = null; 
            publicKey = null; 
        }
        catch (Exception ex)
        {
            tempEphemeralHandle?.Dispose();
            if (tempPrivateKeyBytes != null) SodiumInterop.SecureWipe(tempPrivateKeyBytes);
            if (publicKey != null) SodiumInterop.SecureWipe(publicKey); // Wipe if error occurred

            _ephemeralSecretKeyHandle = null;
            EphemeralX25519PublicKey = null;
            throw new CryptographicException("Failed to generate ephemeral key pair.", ex);
        }
    }

    public Result<SodiumSecureMemoryHandle, ShieldFailure> CalculateSharedSecretAsRecipient(
        ReadOnlySpan<byte> remoteIdentityPublicKeyX, // Alice's IKa_pub
        ReadOnlySpan<byte> remoteEphemeralPublicKeyX, // Alice's Ea_pub
        uint? usedLocalOpkId, // ID of Bob's OPK used by Alice
        ReadOnlySpan<byte> info)
    {
        // ... (Checks for disposed, info, handles, remote keys remain) ...
        if (_disposed) throw new ObjectDisposedException(nameof(LocalKeyMaterial));
        if (info.IsEmpty)
            return Result<SodiumSecureMemoryHandle, ShieldFailure>.Err(
                ShieldFailure.DeriveKeyFailed("HKDF info empty."));
        if (remoteIdentityPublicKeyX.Length != Constants.X25519PublicKeySize)
            return Result<SodiumSecureMemoryHandle, ShieldFailure>.Err(
                ShieldFailure.PeerPubKeyFailed("Invalid remote IK length."));
        if (remoteEphemeralPublicKeyX.Length != Constants.X25519PublicKeySize)
            return Result<SodiumSecureMemoryHandle, ShieldFailure>.Err(
                ShieldFailure.PeerPubKeyFailed("Invalid remote EK length."));
        if (_identityX25519SecretKeyHandle == null || _identityX25519SecretKeyHandle.IsInvalid)
            throw new InvalidOperationException("Local IK invalid.");
        if (_signedPreKeySecretKeyHandle == null || _signedPreKeySecretKeyHandle.IsInvalid)
            throw new InvalidOperationException("Local SPK invalid.");

        SodiumSecureMemoryHandle? opkSecretHandle = null;
        if (usedLocalOpkId.HasValue)
        {
            var usedOpk = _oneTimePreKeysInternal?.FirstOrDefault(opk => opk.PreKeyId == usedLocalOpkId.Value);
            if (usedOpk == null || usedOpk.Value.PrivateKeyHandle == null || usedOpk.Value.PrivateKeyHandle.IsInvalid)
            {
                return Result<SodiumSecureMemoryHandle, ShieldFailure>.Err(
                    ShieldFailure.HandshakeFailed($"Local OPK ID {usedLocalOpkId.Value} not found/invalid."));
            }

            opkSecretHandle = usedOpk.Value.PrivateKeyHandle; // Get handle, don't dispose it here!
        }

        byte[]? identitySecretCopy = null;
        byte[]? signedPreKeySecretCopy = null;
        byte[]? oneTimePreKeySecretCopy = null;
        byte[]? dh1 = null;
        byte[]? dh2 = null;
        byte[]? dh3 = null;
        byte[]? dh4 = null;
        byte[]? dhConcatBytes = null;
        byte[]? hkdfOutput = null;
        SodiumSecureMemoryHandle? secureOutputHandle = null;

        try
        {
            identitySecretCopy = new byte[Constants.X25519PrivateKeySize];
            _identityX25519SecretKeyHandle.Read(identitySecretCopy);

            signedPreKeySecretCopy = new byte[Constants.X25519PrivateKeySize];
            _signedPreKeySecretKeyHandle.Read(signedPreKeySecretCopy);

            if (opkSecretHandle != null)
            {
                oneTimePreKeySecretCopy = new byte[Constants.X25519PrivateKeySize];
                opkSecretHandle.Read(oneTimePreKeySecretCopy);
            }

            // DH Calculations
            dh1 = ScalarMult.Mult(identitySecretCopy,
                remoteEphemeralPublicKeyX.ToArray()); // Bob ID Priv (IKb), Alice Eph Pub (Ea)
            dh2 = ScalarMult.Mult(signedPreKeySecretCopy,
                remoteEphemeralPublicKeyX.ToArray()); // Bob SPK Priv, Alice Eph Pub (Ea)
            dh3 = ScalarMult.Mult(signedPreKeySecretCopy,
                remoteIdentityPublicKeyX.ToArray()); // Bob SPK Priv, Alice ID Pub (IKa)
            if (oneTimePreKeySecretCopy != null)
            {
                dh4 = ScalarMult.Mult(oneTimePreKeySecretCopy, remoteEphemeralPublicKeyX.ToArray());
            } // Bob OPK Priv, Alice Eph Pub (Ea)

            // *** ADDED LOGGING ***
            Console.WriteLine($"--- Bob Derivation (Used OPK ID: {usedLocalOpkId?.ToString() ?? "None"}) ---");
            Console.WriteLine($"Bob DH1 (IKb, Ea): {Convert.ToHexString(dh1)}");
            Console.WriteLine($"Bob DH2 (SPKb, Ea): {Convert.ToHexString(dh2)}");
            Console.WriteLine($"Bob DH3 (SPKb, IKa): {Convert.ToHexString(dh3)}");
            if (dh4 != null) Console.WriteLine($"Bob DH4 (OPKb, Ea): {Convert.ToHexString(dh4)}");
            else Console.WriteLine("Bob DH4: null");

            SodiumInterop.SecureWipe(identitySecretCopy);
            identitySecretCopy = null;
            SodiumInterop.SecureWipe(signedPreKeySecretCopy);
            signedPreKeySecretCopy = null;
            if (oneTimePreKeySecretCopy != null)
            {
                SodiumInterop.SecureWipe(oneTimePreKeySecretCopy);
                oneTimePreKeySecretCopy = null;
            }
           
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

            // *** ADDED LOGGING ***
            Console.WriteLine($"Bob IKM (Concat): {Convert.ToHexString(dhConcatBytes)}");
            // *** END LOGGING ***

            // HKDF
            hkdfOutput = new byte[Constants.X25519KeySize];
            Span<byte> hkdfSaltSpan = stackalloc byte[Constants.X25519KeySize]; // Zero salt
            using (HkdfSha256 hkdf = new(dhConcatBytes, hkdfSaltSpan)) // Pass Span for salt
            {
                hkdf.Expand(info, hkdfOutput);
            }
            // Salt span goes out of scope and is cleared

            // *** ADDED LOGGING ***
            Console.WriteLine($"Bob Final Secret (Output): {Convert.ToHexString(hkdfOutput)}");
            // *** END LOGGING ***

            secureOutputHandle = SodiumSecureMemoryHandle.Allocate(hkdfOutput.Length);
            secureOutputHandle.Write(hkdfOutput);

            var returnHandle = secureOutputHandle;
            secureOutputHandle = null; // Transfer ownership
            return Result<SodiumSecureMemoryHandle, ShieldFailure>.Ok(returnHandle);
        }
        catch (Exception ex)
        {
            secureOutputHandle?.Dispose();
            return Result<SodiumSecureMemoryHandle, ShieldFailure>.Err(
                ShieldFailure.DeriveKeyFailed($"Internal error (Bob): {ex.Message}"));
        } // Added inner ex
        finally
        {
            // Wipe heap buffers if not nulled out on success/error paths
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