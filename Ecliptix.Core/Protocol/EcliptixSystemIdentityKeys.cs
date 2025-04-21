using Ecliptix.Core.Protocol.Utilities;
using Sodium;

namespace Ecliptix.Core.Protocol;

public sealed class EcliptixSystemIdentityKeys : IDisposable
{
    private readonly SodiumSecureMemoryHandle _ed25519SecretKeyHandle;
    public byte[] Ed25519PublicKey { get; }

    private readonly SodiumSecureMemoryHandle _identityX25519SecretKeyHandle;
    public byte[] IdentityX25519PublicKey { get; }

    public uint SignedPreKeyId { get; }
    private readonly SodiumSecureMemoryHandle _signedPreKeySecretKeyHandle;
    public byte[] SignedPreKeyPublic { get; }
    public byte[] SignedPreKeySignature { get; }

    private List<OneTimePreKeyLocal> _oneTimePreKeysInternal;

    private SodiumSecureMemoryHandle? _ephemeralSecretKeyHandle;
    public byte[]? EphemeralX25519PublicKey { get; private set; }

    private bool _disposed;

    private EcliptixSystemIdentityKeys(
        SodiumSecureMemoryHandle edSk, byte[] edPk,
        SodiumSecureMemoryHandle idSk, byte[] idPk,
        uint spkId, SodiumSecureMemoryHandle spkSk, byte[] spkPk, byte[] spkSig,
        List<OneTimePreKeyLocal> opks)
    {
        _ed25519SecretKeyHandle = edSk;
        Ed25519PublicKey = edPk;
        _identityX25519SecretKeyHandle = idSk;
        IdentityX25519PublicKey = idPk;
        SignedPreKeyId = spkId;
        _signedPreKeySecretKeyHandle = spkSk;
        SignedPreKeyPublic = spkPk;
        SignedPreKeySignature = spkSig;
        _oneTimePreKeysInternal = opks;
        _disposed = false;
    }

    public static Result<EcliptixSystemIdentityKeys, ShieldFailure> Create(uint oneTimeKeyCount)
    {
        if (oneTimeKeyCount > int.MaxValue)
            return Result<EcliptixSystemIdentityKeys, ShieldFailure>.Err(
                ShieldFailure.InvalidInput("Requested one-time key count exceeds practical limits."));

        SodiumSecureMemoryHandle? edSkHandle = null;
        byte[]? edPk = null;
        SodiumSecureMemoryHandle? idXSkHandle = null;
        byte[]? idXPk = null;
        uint spkId = 0;
        SodiumSecureMemoryHandle? spkSkHandle = null;
        byte[]? spkPk = null;
        byte[]? spkSig = null;
        List<OneTimePreKeyLocal>? opks = null;

        try
        {
            var overallResult = GenerateEd25519Keys()
                .Bind(edKeys =>
                {
                    (edSkHandle, edPk) = edKeys;
                    return GenerateX25519IdentityKeys();
                })
                .Bind(idKeys =>
                {
                    (idXSkHandle, idXPk) = idKeys;
                    spkId = GenerateRandomUInt32();
                    return GenerateX25519SignedPreKey(spkId);
                })
                .Bind(spkKeys =>
                {
                    (spkSkHandle, spkPk) = spkKeys;
                    return SignSignedPreKey(edSkHandle!, spkPk!);
                })
                .Bind(signature =>
                {
                    spkSig = signature;
                    return GenerateOneTimePreKeys(oneTimeKeyCount);
                })
                .Bind(generatedOpks =>
                {
                    opks = generatedOpks;
                    var material = new EcliptixSystemIdentityKeys(edSkHandle!, edPk!, idXSkHandle!, idXPk!, spkId, spkSkHandle!,
                        spkPk!, spkSig!, opks);
                    return Result<EcliptixSystemIdentityKeys, ShieldFailure>.Ok(material);
                });

            if (overallResult.IsErr)
            {
                edSkHandle?.Dispose();
                idXSkHandle?.Dispose();
                spkSkHandle?.Dispose();
                if (opks != null)
                    foreach (var opk in opks)
                        opk.Dispose();
            }

            return overallResult;
        }
        catch (Exception ex)
        {
            edSkHandle?.Dispose();
            idXSkHandle?.Dispose();
            spkSkHandle?.Dispose();
            if (opks != null)
                foreach (var opk in opks)
                    opk.Dispose();
            return Result<EcliptixSystemIdentityKeys, ShieldFailure>.Err(
                ShieldFailure.Generic($"Unexpected error initializing LocalKeyMaterial: {ex.Message}", ex));
        }
    }

    private static Result<(SodiumSecureMemoryHandle skHandle, byte[] pk), ShieldFailure> GenerateEd25519Keys()
    {
        SodiumSecureMemoryHandle? skHandle = null;
        byte[]? skBytes = null;
        byte[]? pkBytes = null;
        try
        {
            return Result<(SodiumSecureMemoryHandle skHandle, byte[] pk), ShieldFailure>.Try(func: () =>
            {
                KeyPair edKeyPair = PublicKeyAuth.GenerateKeyPair();
                skBytes = edKeyPair.PrivateKey;
                pkBytes = edKeyPair.PublicKey;
                skHandle = SodiumSecureMemoryHandle.Allocate(Constants.Ed25519SecretKeySize).Unwrap();
                skHandle.Write(skBytes).Unwrap();
                return (skHandle, pkBytes);
            }, errorMapper: ex => ShieldFailure.KeyGeneration("Failed to generate Ed25519 key pair.", ex));
        }
        finally
        {
            if (skBytes != null) SodiumInterop.SecureWipe(skBytes).IgnoreResult();
        }
    }

    private static Result<(SodiumSecureMemoryHandle skHandle, byte[] pk), ShieldFailure> GenerateX25519IdentityKeys() =>
        GenerateX25519KeyPair("Identity");

    private static Result<(SodiumSecureMemoryHandle skHandle, byte[] pk), ShieldFailure>
        GenerateX25519SignedPreKey(uint id) => GenerateX25519KeyPair($"Signed PreKey (ID: {id})");

    private static Result<(SodiumSecureMemoryHandle skHandle, byte[] pk), ShieldFailure> GenerateX25519KeyPair(
        string keyPurpose)
    {
        SodiumSecureMemoryHandle? skHandle = null;
        byte[]? skBytes = null;
        byte[]? pkBytes = null;
        byte[]? tempPrivCopy = null;
        try
        {
            var allocResult = SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize);
            if (allocResult.IsErr)
                return Result<(SodiumSecureMemoryHandle, byte[]), ShieldFailure>.Err(allocResult.UnwrapErr());
            skHandle = allocResult.Unwrap();
            skBytes = SodiumCore.GetRandomBytes(Constants.X25519PrivateKeySize);
            var writeResult = skHandle.Write(skBytes);
            if (writeResult.IsErr)
            {
                skHandle.Dispose();
                return Result<(SodiumSecureMemoryHandle, byte[]), ShieldFailure>.Err(writeResult.UnwrapErr());
            }

            SodiumInterop.SecureWipe(skBytes).IgnoreResult();
            skBytes = null;
            tempPrivCopy = new byte[Constants.X25519PrivateKeySize];
            var readResult = skHandle.Read(tempPrivCopy);
            if (readResult.IsErr)
            {
                skHandle.Dispose();
                SodiumInterop.SecureWipe(tempPrivCopy).IgnoreResult();
                return Result<(SodiumSecureMemoryHandle, byte[]), ShieldFailure>.Err(readResult.UnwrapErr());
            }

            var deriveResult = Result<byte[], ShieldFailure>.Try(() => ScalarMult.Base(tempPrivCopy),
                ex => ShieldFailure.DeriveKey($"Failed to derive {keyPurpose} public key.", ex));
            SodiumInterop.SecureWipe(tempPrivCopy).IgnoreResult();
            tempPrivCopy = null;
            if (deriveResult.IsErr)
            {
                skHandle.Dispose();
                return Result<(SodiumSecureMemoryHandle, byte[]), ShieldFailure>.Err(deriveResult.UnwrapErr());
            }

            pkBytes = deriveResult.Unwrap();
            if (pkBytes.Length != Constants.X25519PublicKeySize)
            {
                skHandle.Dispose();
                SodiumInterop.SecureWipe(pkBytes).IgnoreResult();
                return Result<(SodiumSecureMemoryHandle, byte[]), ShieldFailure>.Err(
                    ShieldFailure.DeriveKey($"Derived {keyPurpose} public key has incorrect size."));
            }

            return Result<(SodiumSecureMemoryHandle, byte[]), ShieldFailure>.Ok((skHandle, pkBytes));
        }
        catch (Exception ex)
        {
            skHandle?.Dispose();
            if (skBytes != null) SodiumInterop.SecureWipe(skBytes).IgnoreResult();
            if (tempPrivCopy != null) SodiumInterop.SecureWipe(tempPrivCopy).IgnoreResult();
            return Result<(SodiumSecureMemoryHandle, byte[]), ShieldFailure>.Err(
                ShieldFailure.KeyGeneration($"Unexpected error generating {keyPurpose} key pair.", ex));
        }
    }

    private static Result<byte[], ShieldFailure> SignSignedPreKey(SodiumSecureMemoryHandle edSkHandle, byte[] spkPk)
    {
        byte[]? tempEdSignKeyCopy = null;
        byte[]? signature = null;
        try
        {
            tempEdSignKeyCopy = new byte[Constants.Ed25519SecretKeySize];
            var readResult = edSkHandle.Read(tempEdSignKeyCopy);
            if (readResult.IsErr) return Result<byte[], ShieldFailure>.Err(readResult.UnwrapErr());
            var signResult = Result<byte[], ShieldFailure>.Try(
                () => PublicKeyAuth.SignDetached(spkPk, tempEdSignKeyCopy),
                ex => ShieldFailure.Generic("Failed to sign signed prekey public key.", ex));
            if (signResult.IsErr) return signResult;
            signature = signResult.Unwrap();
            if (signature.Length != Constants.Ed25519SignatureSize)
            {
                SodiumInterop.SecureWipe(signature).IgnoreResult();
                return Result<byte[], ShieldFailure>.Err(
                    ShieldFailure.Generic($"Generated SPK signature has incorrect size ({signature.Length})."));
            }

            return Result<byte[], ShieldFailure>.Ok(signature);
        }
        finally
        {
            if (tempEdSignKeyCopy != null) SodiumInterop.SecureWipe(tempEdSignKeyCopy).IgnoreResult();
        }
    }

    private static Result<List<OneTimePreKeyLocal>, ShieldFailure> GenerateOneTimePreKeys(uint count)
    {
        if (count == 0) return Result<List<OneTimePreKeyLocal>, ShieldFailure>.Ok(new List<OneTimePreKeyLocal>());
        var opks = new List<OneTimePreKeyLocal>((int)count);
        var usedIds = new HashSet<uint>((int)count);
        uint idCounter = 2;
        try
        {
            for (int i = 0; i < count; i++)
            {
                uint id = idCounter++;
                while (usedIds.Contains(id))
                {
                    id = GenerateRandomUInt32();
                }

                usedIds.Add(id);
                var opkResult = OneTimePreKeyLocal.Generate(id);
                if (opkResult.IsErr)
                {
                    foreach (var generatedOpk in opks) generatedOpk.Dispose();
                    return Result<List<OneTimePreKeyLocal>, ShieldFailure>.Err(opkResult.UnwrapErr());
                }

                opks.Add(opkResult.Unwrap());
            }

            return Result<List<OneTimePreKeyLocal>, ShieldFailure>.Ok(opks);
        }
        catch (Exception ex)
        {
            foreach (var generatedOpk in opks) generatedOpk.Dispose();
            return Result<List<OneTimePreKeyLocal>, ShieldFailure>.Err(
                ShieldFailure.KeyGeneration("Unexpected error generating one-time prekeys.", ex));
        }
    }

    private static uint GenerateRandomUInt32()
    {
        byte[] buffer = SodiumCore.GetRandomBytes(sizeof(uint));
        return BitConverter.ToUInt32(buffer, 0);
    }

    public Result<LocalPublicKeyBundle, ShieldFailure> CreatePublicBundle()
    {
        if (_disposed)
            return Result<LocalPublicKeyBundle, ShieldFailure>.Err(
                ShieldFailure.ObjectDisposed(nameof(EcliptixSystemIdentityKeys)));

        return Result<LocalPublicKeyBundle, ShieldFailure>.Try(
            func: () =>
            {
                List<OneTimePreKeyRecord> opkRecords = _oneTimePreKeysInternal
                    .Select(opkLocal => new OneTimePreKeyRecord(opkLocal.PreKeyId, opkLocal.PublicKey))
                    .ToList();

                var bundle = new LocalPublicKeyBundle(
                    IdentityEd25519: this.Ed25519PublicKey,
                    IdentityX25519: this.IdentityX25519PublicKey,
                    SignedPreKeyId: this.SignedPreKeyId,
                    SignedPreKeyPublic: this.SignedPreKeyPublic,
                    SignedPreKeySignature: this.SignedPreKeySignature,
                    OneTimePreKeys: opkRecords,
                    EphemeralX25519: this.EphemeralX25519PublicKey
                );
                return bundle;
            },
            errorMapper: ex => ShieldFailure.Generic("Failed to create public key bundle.", ex)
        );
    }

    public Result<Unit, ShieldFailure> GenerateEphemeralKeyPair()
    {
        if (_disposed)
            return Result<Unit, ShieldFailure>.Err(ShieldFailure.ObjectDisposed(nameof(EcliptixSystemIdentityKeys)));

        _ephemeralSecretKeyHandle?.Dispose();
        _ephemeralSecretKeyHandle = null;
        if (EphemeralX25519PublicKey != null)
            SodiumInterop.SecureWipe(EphemeralX25519PublicKey).IgnoreResult();
        EphemeralX25519PublicKey = null;

        var generationResult = GenerateX25519KeyPair("Ephemeral");

        return generationResult.Map(keys =>
        {
            _ephemeralSecretKeyHandle = keys.skHandle;
            EphemeralX25519PublicKey = keys.pk;
            return Unit.Value;
        });
    }


    public Result<SodiumSecureMemoryHandle, ShieldFailure> X3dhDeriveSharedSecret(
        LocalPublicKeyBundle remoteBundle,
        ReadOnlySpan<byte> info)
    {
        SodiumSecureMemoryHandle? ephemeralHandleUsed = null;
        SodiumSecureMemoryHandle? secureOutputHandle = null;
        byte[]? ephemeralSecretCopy = null;
        byte[]? identitySecretCopy = null;
        byte[]? dh1 = null, dh2 = null, dh3 = null, dh4 = null, dhConcatBytes = null, hkdfOutput = null;
        byte[]? infoCopy = null;

        try
        {
            infoCopy = info.ToArray();

            var validationResult = CheckDisposed()
                .Bind(_ => ValidateHkdfInfo(infoCopy))
                .Bind(_ => ValidateRemoteBundle(remoteBundle))
                .Bind(_ => EnsureLocalKeysValid());

            if (validationResult.IsErr)
                return Result<SodiumSecureMemoryHandle, ShieldFailure>.Err(validationResult.UnwrapErr());

            Result<SodiumSecureMemoryHandle, ShieldFailure> processResult = _ephemeralSecretKeyHandle!
                .ReadBytes(Constants.X25519PrivateKeySize)
                .Bind(ephBytes =>
                {
                    ephemeralSecretCopy = ephBytes;
                    return _identityX25519SecretKeyHandle!.ReadBytes(Constants.X25519PrivateKeySize);
                })
                .Bind(idBytes =>
                {
                    identitySecretCopy = idBytes;
                    ephemeralHandleUsed = _ephemeralSecretKeyHandle;
                    _ephemeralSecretKeyHandle = null;
                    return Result<(byte[], byte[], byte[], byte[]?), ShieldFailure>.Try(
                        func: () =>
                        {
                            byte[] dh1 = ScalarMult.Mult(ephemeralSecretCopy!, remoteBundle.IdentityX25519); // DH1
                            byte[] dh2 = ScalarMult.Mult(ephemeralSecretCopy!, remoteBundle.SignedPreKeyPublic); // DH2
                            byte[] dh3 = ScalarMult.Mult(identitySecretCopy!, remoteBundle.SignedPreKeyPublic); // DH3
                            byte[]? dh4 = null;
                            OneTimePreKeyRecord? remoteOpk = remoteBundle.OneTimePreKeys?.FirstOrDefault();
                            if (remoteOpk?.PublicKey is { Length: Constants.X25519PublicKeySize })
                            {
                                dh4 = ScalarMult.Mult(ephemeralSecretCopy!, remoteOpk.PublicKey); // DH4
                            }

                            return (dh1, dh2, dh3, dh4);
                        },
                        errorMapper: ex => ShieldFailure.DeriveKey("Failed during DH calculation (Alice).", ex)
                    );
                })
                .Bind(dhResults =>
                {
                    (dh1, dh2, dh3, dh4) = dhResults;
                    SodiumInterop.SecureWipe(ephemeralSecretCopy!).IgnoreResult();
                    ephemeralSecretCopy = null;
                    SodiumInterop.SecureWipe(identitySecretCopy!).IgnoreResult();
                    identitySecretCopy = null;
                    dhConcatBytes = ConcatenateDhResultsInCanonicalOrder(dh1, dh2, dh3, dh4);
                    hkdfOutput = new byte[Constants.X25519KeySize];
                    byte[] capturedInfoCopy = infoCopy;
                    return Result<Unit, ShieldFailure>.Try(
                        action: () =>
                        {
                            Span<byte> f32 = stackalloc byte[Constants.X25519KeySize];
                            f32.Fill(0xFF);
                            Span<byte> hkdfSaltSpan = stackalloc byte[Constants.X25519KeySize];
                            byte[] ikm = new byte[f32.Length + dhConcatBytes.Length];
                            Buffer.BlockCopy(f32.ToArray(), 0, ikm, 0, f32.Length);
                            Buffer.BlockCopy(dhConcatBytes, 0, ikm, f32.Length, dhConcatBytes.Length);
                            using HkdfSha256 hkdf = new HkdfSha256(ikm, hkdfSaltSpan);
                            hkdf.Expand(capturedInfoCopy, hkdfOutput);
                        },
                        errorMapper: ex => ShieldFailure.DeriveKey("Failed during HKDF expansion (Alice).", ex)
                    );
                })
                // --- Corrected Final Bind ---
                .Bind(_ => // If HKDF succeeds...
                {
                    // Allocate the handle first
                    return SodiumSecureMemoryHandle.Allocate(hkdfOutput!.Length)
                        .Bind(allocatedHandle => // If Allocate is Ok, proceed with the handle
                        {
                            // Write using the allocated handle. This returns Result<Unit, TE>.
                            return allocatedHandle.Write(hkdfOutput!)
                                // If Write is Ok(Unit), map the successful Unit result
                                // back to the original allocatedHandle we want to return.
                                .Map(_ => allocatedHandle);
                            // The result of this Map is Result<SodiumSecureMemoryHandle, TE>
                        });
                    // The result of the outer Bind is now correctly Result<SodiumSecureMemoryHandle, TE>
                });
            // --- End Corrected Final Bind ---

            // Alice -> keypair ->extract_public bundle ----> 3DH server (process it) shared_key 32 bytes.
            
            // Unterval -> 100 keys. 4 hours realod.
            // ROOT key -> CHAIN SENDER | CHINE RECIEVER ( 2 object ) -> KEY -> iter +1 index upgrade, Create new Message KEY.[] index
            // Dh
            
            // CLIENT -> reload CHAIN -> NEW ALL KEYS, reset index-> generate new MessageKey. -> New (PrivaTEkEY) DHPublicKey
            
            if (processResult.IsErr)
            {
                return processResult;
            }
            else
            {
                secureOutputHandle = processResult.Unwrap();
                var returnHandle = secureOutputHandle;
                secureOutputHandle = null;
                return Result<SodiumSecureMemoryHandle, ShieldFailure>.Ok(returnHandle);
            }
        }
        finally
        {
            ephemeralHandleUsed?.Dispose();
            secureOutputHandle?.Dispose();
            if (infoCopy != null) SodiumInterop.SecureWipe(infoCopy).IgnoreResult();
            if (ephemeralSecretCopy != null) SodiumInterop.SecureWipe(ephemeralSecretCopy).IgnoreResult();
            if (identitySecretCopy != null) SodiumInterop.SecureWipe(identitySecretCopy).IgnoreResult();
            if (dh1 != null) SodiumInterop.SecureWipe(dh1).IgnoreResult();
            if (dh2 != null) SodiumInterop.SecureWipe(dh2).IgnoreResult();
            if (dh3 != null) SodiumInterop.SecureWipe(dh3).IgnoreResult();
            if (dh4 != null) SodiumInterop.SecureWipe(dh4).IgnoreResult();
            if (dhConcatBytes != null) SodiumInterop.SecureWipe(dhConcatBytes).IgnoreResult();
            if (hkdfOutput != null) SodiumInterop.SecureWipe(hkdfOutput).IgnoreResult();
        }
    }

    private Result<Unit, ShieldFailure> CheckDisposed() => _disposed
        ? Result<Unit, ShieldFailure>.Err(ShieldFailure.ObjectDisposed(nameof(EcliptixSystemIdentityKeys)))
        : Result<Unit, ShieldFailure>.Ok(Unit.Value);

    private static Result<Unit, ShieldFailure> ValidateHkdfInfo(byte[]? infoCopy) =>
        (infoCopy == null || infoCopy.Length == 0)
            ? Result<Unit, ShieldFailure>.Err(ShieldFailure.DeriveKey("HKDF info cannot be empty."))
            : Result<Unit, ShieldFailure>.Ok(Unit.Value);

    private static Result<Unit, ShieldFailure> ValidateRemoteBundle(LocalPublicKeyBundle? remoteBundle)
    {
        if (remoteBundle == null)
            return Result<Unit, ShieldFailure>.Err(ShieldFailure.InvalidInput("Remote bundle cannot be null."));
        if (remoteBundle.IdentityX25519 is not { Length: Constants.X25519PublicKeySize })
            return Result<Unit, ShieldFailure>.Err(ShieldFailure.PeerPubKey("Invalid remote IdentityX25519 key."));
        if (remoteBundle.SignedPreKeyPublic is not { Length: Constants.X25519PublicKeySize })
            return Result<Unit, ShieldFailure>.Err(ShieldFailure.PeerPubKey("Invalid remote SignedPreKeyPublic key."));
        return Result<Unit, ShieldFailure>.Ok(Unit.Value);
    }

    private Result<Unit, ShieldFailure> EnsureLocalKeysValid()
    {
        if (_ephemeralSecretKeyHandle == null || _ephemeralSecretKeyHandle.IsInvalid)
            return Result<Unit, ShieldFailure>.Err(
                ShieldFailure.PrepareLocal("Local ephemeral key is missing or invalid."));
        if (_identityX25519SecretKeyHandle.IsInvalid)
            return Result<Unit, ShieldFailure>.Err(
                ShieldFailure.PrepareLocal("Local identity key is missing or invalid."));
        return Result<Unit, ShieldFailure>.Ok(Unit.Value);
    }

    private static byte[] ConcatenateDhResultsInCanonicalOrder(
        byte[] dhInitiatorEphResponderId, // DH1
        byte[] dhInitiatorEphResponderSpk, // DH2
        byte[] dhInitiatorIdResponderSpk, // DH3
        byte[]? dhInitiatorEphResponderOpk) // DH4
    {
        int totalDhLength = dhInitiatorEphResponderId.Length +
                            dhInitiatorEphResponderSpk.Length +
                            dhInitiatorIdResponderSpk.Length +
                            (dhInitiatorEphResponderOpk?.Length ?? 0);
        byte[] dhConcatBytes = new byte[totalDhLength];
        int currentOffset = 0;
        Buffer.BlockCopy(dhInitiatorEphResponderId, 0, dhConcatBytes, currentOffset, dhInitiatorEphResponderId.Length);
        currentOffset += dhInitiatorEphResponderId.Length;
        Buffer.BlockCopy(dhInitiatorEphResponderSpk, 0, dhConcatBytes, currentOffset,
            dhInitiatorEphResponderSpk.Length);
        currentOffset += dhInitiatorEphResponderSpk.Length;
        Buffer.BlockCopy(dhInitiatorIdResponderSpk, 0, dhConcatBytes, currentOffset, dhInitiatorIdResponderSpk.Length);
        currentOffset += dhInitiatorIdResponderSpk.Length;
        if (dhInitiatorEphResponderOpk != null)
            Buffer.BlockCopy(dhInitiatorEphResponderOpk, 0, dhConcatBytes, currentOffset,
                dhInitiatorEphResponderOpk.Length);
        return dhConcatBytes;
    }

    public static Result<bool, ShieldFailure> VerifyRemoteSpkSignature(
        ReadOnlySpan<byte> remoteIdentityEd25519,
        ReadOnlySpan<byte> remoteSpkPublic,
        ReadOnlySpan<byte> remoteSpkSignature)
    {
        byte[]? identityCopy = null;
        byte[]? spkPublicCopy = null;
        byte[]? signatureCopy = null;
        try
        {
            identityCopy = remoteIdentityEd25519.ToArray();
            spkPublicCopy = remoteSpkPublic.ToArray();
            signatureCopy = remoteSpkSignature.ToArray();
            if (identityCopy.Length != Constants.Ed25519PublicKeySize)
                return Result<bool, ShieldFailure>.Err(
                    ShieldFailure.PeerPubKey($"Invalid remote Ed25519 identity key length ({identityCopy.Length})."));
            if (spkPublicCopy.Length != Constants.X25519PublicKeySize)
                return Result<bool, ShieldFailure>.Err(
                    ShieldFailure.PeerPubKey(
                        $"Invalid remote Signed PreKey public key length ({spkPublicCopy.Length})."));
            if (signatureCopy.Length != Constants.Ed25519SignatureSize)
                return Result<bool, ShieldFailure>.Err(
                    ShieldFailure.Handshake(
                        $"Invalid remote Signed PreKey signature length ({signatureCopy.Length})."));
            byte[] capturedIdentity = identityCopy;
            byte[] capturedSpkPublic = spkPublicCopy;
            byte[] capturedSignature = signatureCopy;
            return Result<bool, ShieldFailure>.Try(
                func: () => PublicKeyAuth.VerifyDetached(capturedSignature, capturedSpkPublic, capturedIdentity),
                errorMapper: ex =>
                    ShieldFailure.Handshake($"Internal error during signature verification: {ex.Message}", ex));
        }
        finally
        {
            if (identityCopy != null) SodiumInterop.SecureWipe(identityCopy).IgnoreResult();
            if (spkPublicCopy != null) SodiumInterop.SecureWipe(spkPublicCopy).IgnoreResult();
            if (signatureCopy != null) SodiumInterop.SecureWipe(signatureCopy).IgnoreResult();
        }
    }

    public Result<SodiumSecureMemoryHandle, ShieldFailure> CalculateSharedSecretAsRecipient(
        ReadOnlySpan<byte> remoteIdentityPublicKeyX,
        ReadOnlySpan<byte> remoteEphemeralPublicKeyX,
        uint? usedLocalOpkId,
        ReadOnlySpan<byte> info)
    {
        SodiumSecureMemoryHandle? secureOutputHandle = null;
        byte[]? identitySecretCopy = null;
        byte[]? signedPreKeySecretCopy = null;
        byte[]? oneTimePreKeySecretCopy = null;
        byte[]? dh1 = null, dh2 = null, dh3 = null, dh4 = null, dhConcatBytes = null, hkdfOutput = null;
        SodiumSecureMemoryHandle? opkSecretHandle = null;
        byte[]? remoteIdentityCopy = null;
        byte[]? remoteEphemeralCopy = null;
        byte[]? infoCopy = null;

        try
        {
            remoteIdentityCopy = remoteIdentityPublicKeyX.ToArray();
            remoteEphemeralCopy = remoteEphemeralPublicKeyX.ToArray();
            infoCopy = info.ToArray();

            var validationResult = CheckDisposed()
                .Bind(_ => ValidateHkdfInfo(infoCopy))
                .Bind(_ => ValidateRemoteRecipientKeys(remoteIdentityCopy, remoteEphemeralCopy))
                .Bind(_ => EnsureLocalRecipientKeysValid());

            if (validationResult.IsErr)
                return Result<SodiumSecureMemoryHandle, ShieldFailure>.Err(validationResult.UnwrapErr());

            if (usedLocalOpkId.HasValue)
            {
                var findOpkResult = FindLocalOpkHandle(usedLocalOpkId.Value);
                if (findOpkResult.IsErr)
                    return Result<SodiumSecureMemoryHandle, ShieldFailure>.Err(findOpkResult.UnwrapErr());
                opkSecretHandle = findOpkResult.Unwrap();
            }

            byte[] capturedRemoteIdentity = remoteIdentityCopy;
            byte[] capturedRemoteEphemeral = remoteEphemeralCopy;
            byte[] capturedInfo = infoCopy;

            Result<SodiumSecureMemoryHandle, ShieldFailure> processResult = _identityX25519SecretKeyHandle!
                .ReadBytes(Constants.X25519PrivateKeySize)
                .Bind(idBytes =>
                {
                    identitySecretCopy = idBytes;
                    return _signedPreKeySecretKeyHandle!.ReadBytes(Constants.X25519PrivateKeySize);
                })
                .Bind(spkBytes =>
                {
                    signedPreKeySecretCopy = spkBytes;
                    if (opkSecretHandle != null)
                    {
                        return opkSecretHandle.ReadBytes(Constants.X25519PrivateKeySize).Map(opkBytes =>
                        {
                            oneTimePreKeySecretCopy = opkBytes;
                            return Unit.Value;
                        });
                    }
                    else
                    {
                        return Result<Unit, ShieldFailure>.Ok(Unit.Value);
                    }
                })
                .Bind(_ =>
                {
                    return Result<(byte[], byte[], byte[], byte[]?), ShieldFailure>.Try(func: () =>
                    {
                        byte[] dh1 =
                            ScalarMult.Mult(identitySecretCopy!,
                                capturedRemoteEphemeral); // DH1 (Bob_identity * Alice_ephemeral)
                        byte[] dh2 =
                            ScalarMult.Mult(signedPreKeySecretCopy!,
                                capturedRemoteEphemeral); // DH2 (Bob_spk * Alice_ephemeral)
                        byte[] dh3 =
                            ScalarMult.Mult(signedPreKeySecretCopy!,
                                capturedRemoteIdentity); // DH3 (Bob_spk * Alice_identity)
                        byte[]? dh4 = (oneTimePreKeySecretCopy != null)
                            ? ScalarMult.Mult(oneTimePreKeySecretCopy, capturedRemoteEphemeral) // DH4
                            : null;
                        return (dh1, dh2, dh3, dh4);
                    }, errorMapper: ex => ShieldFailure.DeriveKey("Failed during DH calculation (Bob).", ex));
                })
                .Bind(dhResults =>
                {
                    (dh1, dh2, dh3, dh4) = dhResults;
                    SodiumInterop.SecureWipe(identitySecretCopy!).IgnoreResult();
                    identitySecretCopy = null;
                    SodiumInterop.SecureWipe(signedPreKeySecretCopy!).IgnoreResult();
                    signedPreKeySecretCopy = null;
                    if (oneTimePreKeySecretCopy != null)
                    {
                        SodiumInterop.SecureWipe(oneTimePreKeySecretCopy).IgnoreResult();
                        oneTimePreKeySecretCopy = null;
                    }

                    dhConcatBytes = ConcatenateDhResultsInCanonicalOrder(dh1, dh2, dh3, dh4);
                    hkdfOutput = new byte[Constants.X25519KeySize];
                    return Result<Unit, ShieldFailure>.Try(action: () =>
                    {
                        Span<byte> f32 = stackalloc byte[Constants.X25519KeySize];
                        f32.Fill(0xFF);
                        Span<byte> hkdfSaltSpan = stackalloc byte[Constants.X25519KeySize];
                        byte[] ikm = new byte[f32.Length + dhConcatBytes.Length];
                        Buffer.BlockCopy(f32.ToArray(), 0, ikm, 0, f32.Length);
                        Buffer.BlockCopy(dhConcatBytes, 0, ikm, f32.Length, dhConcatBytes.Length);
                        using HkdfSha256 hkdf = new HkdfSha256(ikm, hkdfSaltSpan);
                        hkdf.Expand(capturedInfo, hkdfOutput);
                    }, errorMapper: ex => ShieldFailure.DeriveKey("Failed during HKDF expansion (Bob).", ex));
                })
                .Bind(_ =>
                {
                    return SodiumSecureMemoryHandle.Allocate(hkdfOutput!.Length)
                        .Bind(allocatedHandle =>
                        {
                            return allocatedHandle.Write(hkdfOutput!)
                                .Map(_ => allocatedHandle);
                        });
                });

            if (processResult.IsErr)
            {
                return processResult;
            }
            else
            {
                secureOutputHandle = processResult.Unwrap();
                SodiumSecureMemoryHandle returnHandle = secureOutputHandle;
                secureOutputHandle = null;
                return Result<SodiumSecureMemoryHandle, ShieldFailure>.Ok(returnHandle);
            }
        }
        finally
        {
            secureOutputHandle?.Dispose();
            if (remoteIdentityCopy != null) SodiumInterop.SecureWipe(remoteIdentityCopy).IgnoreResult();
            if (remoteEphemeralCopy != null) SodiumInterop.SecureWipe(remoteEphemeralCopy).IgnoreResult();
            if (infoCopy != null) SodiumInterop.SecureWipe(infoCopy).IgnoreResult();
            if (identitySecretCopy != null) SodiumInterop.SecureWipe(identitySecretCopy).IgnoreResult();
            if (signedPreKeySecretCopy != null) SodiumInterop.SecureWipe(signedPreKeySecretCopy).IgnoreResult();
            if (oneTimePreKeySecretCopy != null) SodiumInterop.SecureWipe(oneTimePreKeySecretCopy).IgnoreResult();
            if (dh1 != null) SodiumInterop.SecureWipe(dh1).IgnoreResult();
            if (dh2 != null) SodiumInterop.SecureWipe(dh2).IgnoreResult();
            if (dh3 != null) SodiumInterop.SecureWipe(dh3).IgnoreResult();
            if (dh4 != null) SodiumInterop.SecureWipe(dh4).IgnoreResult();
            if (dhConcatBytes != null) SodiumInterop.SecureWipe(dhConcatBytes).IgnoreResult();
            if (hkdfOutput != null) SodiumInterop.SecureWipe(hkdfOutput).IgnoreResult();
        }
    }

    private static Result<Unit, ShieldFailure> ValidateRemoteRecipientKeys(byte[]? remoteIdentityPublicKeyX,
        byte[]? remoteEphemeralPublicKeyX)
    {
        if (remoteIdentityPublicKeyX is not { Length: Constants.X25519PublicKeySize })
            return Result<Unit, ShieldFailure>.Err(ShieldFailure.PeerPubKey("Invalid remote Identity key length."));
        if (remoteEphemeralPublicKeyX is not { Length: Constants.X25519PublicKeySize })
            return Result<Unit, ShieldFailure>.Err(ShieldFailure.PeerPubKey("Invalid remote Ephemeral key length."));
        return Result<Unit, ShieldFailure>.Ok(Unit.Value);
    }

    private Result<Unit, ShieldFailure> EnsureLocalRecipientKeysValid()
    {
        if (_identityX25519SecretKeyHandle == null || _identityX25519SecretKeyHandle.IsInvalid)
            return Result<Unit, ShieldFailure>.Err(
                ShieldFailure.PrepareLocal("Local identity key is missing or invalid."));
        if (_signedPreKeySecretKeyHandle == null || _signedPreKeySecretKeyHandle.IsInvalid)
            return Result<Unit, ShieldFailure>.Err(
                ShieldFailure.PrepareLocal("Local signed prekey is missing or invalid."));
        return Result<Unit, ShieldFailure>.Ok(Unit.Value);
    }

    private Result<SodiumSecureMemoryHandle?, ShieldFailure> FindLocalOpkHandle(uint opkId)
    {
        if (_oneTimePreKeysInternal == null)
            return Result<SodiumSecureMemoryHandle?, ShieldFailure>.Err(
                ShieldFailure.PrepareLocal("One-time prekey list is missing."));
        foreach (var opk in _oneTimePreKeysInternal)
        {
            if (opk.PreKeyId == opkId)
            {
                if (opk.PrivateKeyHandle == null || opk.PrivateKeyHandle.IsInvalid)
                    return Result<SodiumSecureMemoryHandle?, ShieldFailure>.Err(
                        ShieldFailure.PrepareLocal($"Local OPK ID {opkId} found but its handle is invalid."));
                return Result<SodiumSecureMemoryHandle?, ShieldFailure>.Ok(opk.PrivateKeyHandle);
            }
        }

        return Result<SodiumSecureMemoryHandle?, ShieldFailure>.Err(
            ShieldFailure.Handshake($"Local OPK ID {opkId} not found."));
    }

    private static byte[] ConcatenateBobDhResults(byte[] dh1, byte[] dh2, byte[] dh3, byte[]? dh4)
    {
        int totalDhLength = dh1.Length + dh2.Length + dh3.Length + (dh4?.Length ?? 0);
        byte[] dhConcatBytes = new byte[totalDhLength];
        int currentOffset = 0;
        Buffer.BlockCopy(dh1, 0, dhConcatBytes, currentOffset, dh1.Length);
        currentOffset += dh1.Length;
        Buffer.BlockCopy(dh2, 0, dhConcatBytes, currentOffset, dh2.Length);
        currentOffset += dh2.Length;
        Buffer.BlockCopy(dh3, 0, dhConcatBytes, currentOffset, dh3.Length);
        currentOffset += dh3.Length;
        if (dh4 != null) Buffer.BlockCopy(dh4, 0, dhConcatBytes, currentOffset, dh4.Length);
        return dhConcatBytes;
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
                SecureCleanupLogic();
            }

            _disposed = true;
        }
    }

    private void SecureCleanupLogic()
    {
        _ed25519SecretKeyHandle?.Dispose();
        _identityX25519SecretKeyHandle?.Dispose();
        _signedPreKeySecretKeyHandle?.Dispose();
        _ephemeralSecretKeyHandle?.Dispose();
        if (_oneTimePreKeysInternal != null)
        {
            foreach (OneTimePreKeyLocal opk in _oneTimePreKeysInternal)
            {
                opk.Dispose();
            }

            _oneTimePreKeysInternal.Clear();
        }

        _oneTimePreKeysInternal = null!;
        _ephemeralSecretKeyHandle = null;
    }

    ~EcliptixSystemIdentityKeys()
    {
        Dispose(false);
    }
}