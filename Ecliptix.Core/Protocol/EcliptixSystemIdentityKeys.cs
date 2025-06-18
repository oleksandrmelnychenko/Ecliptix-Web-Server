using System.Buffers;
using Ecliptix.Core.Protocol.Failures;
using Ecliptix.Domain.Utilities;
using Sodium;

namespace Ecliptix.Core.Protocol;

public sealed class EcliptixSystemIdentityKeys : IDisposable
{
    private readonly byte[] _ed25519PublicKey;
    private readonly SodiumSecureMemoryHandle _ed25519SecretKeyHandle;
    private readonly SodiumSecureMemoryHandle _identityX25519SecretKeyHandle;
    private readonly uint _signedPreKeyId;
    private readonly byte[] _signedPreKeyPublic;
    private readonly SodiumSecureMemoryHandle _signedPreKeySecretKeyHandle;
    private readonly byte[] _signedPreKeySignature;
    private bool _disposed;
    private SodiumSecureMemoryHandle? _ephemeralSecretKeyHandle;
    private byte[]? _ephemeralX25519PublicKey;
    private List<OneTimePreKeyLocal> _oneTimePreKeysInternal;

    private EcliptixSystemIdentityKeys(
        SodiumSecureMemoryHandle edSk, byte[] edPk,
        SodiumSecureMemoryHandle idSk, byte[] idPk,
        uint spkId, SodiumSecureMemoryHandle spkSk, byte[] spkPk, byte[] spkSig,
        List<OneTimePreKeyLocal> opks)
    {
        _ed25519SecretKeyHandle = edSk;
        _ed25519PublicKey = edPk;
        _identityX25519SecretKeyHandle = idSk;
        IdentityX25519PublicKey = idPk;
        _signedPreKeyId = spkId;
        _signedPreKeySecretKeyHandle = spkSk;
        _signedPreKeyPublic = spkPk;
        _signedPreKeySignature = spkSig;
        _oneTimePreKeysInternal = opks;
        _disposed = false;
    }

    public byte[] IdentityX25519PublicKey { get; }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    public static Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> Create(uint oneTimeKeyCount)
    {
        if (oneTimeKeyCount > int.MaxValue)
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Requested one-time key count exceeds practical limits."));

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
            Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> overallResult =
                GenerateEd25519Keys()
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
                        EcliptixSystemIdentityKeys material = new(edSkHandle!, edPk!, idXSkHandle!, idXPk!, spkId,
                            spkSkHandle!,
                            spkPk!, spkSig!, opks);
                        edSkHandle = null;
                        idXSkHandle = null;
                        spkSkHandle = null;
                        opks = null;
                        return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Ok(material);
                    });

            if (overallResult.IsErr)
            {
                edSkHandle?.Dispose();
                idXSkHandle?.Dispose();
                spkSkHandle?.Dispose();
                if (opks != null)
                {
                    foreach (OneTimePreKeyLocal opk in opks) opk.Dispose();
                }
            }

            return overallResult;
        }
        catch (Exception ex)
        {
            edSkHandle?.Dispose();
            idXSkHandle?.Dispose();
            spkSkHandle?.Dispose();
            if (opks != null)
            {
                foreach (OneTimePreKeyLocal opk in opks) opk.Dispose();
            }

            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic($"Unexpected error initializing LocalKeyMaterial: {ex.Message}", ex));
        }
    }

    private static Result<(SodiumSecureMemoryHandle skHandle, byte[] pk), EcliptixProtocolFailure> GenerateEd25519Keys()
    {
        SodiumSecureMemoryHandle? skHandle = null;
        byte[]? skBytes = null;
        try
        {
            return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Try(() =>
            {
                KeyPair edKeyPair = PublicKeyAuth.GenerateKeyPair();
                skBytes = edKeyPair.PrivateKey;
                byte[] pkBytes = edKeyPair.PublicKey;

                skHandle = SodiumSecureMemoryHandle.Allocate(Constants.Ed25519SecretKeySize).Unwrap();
                skHandle.Write(skBytes).Unwrap();

                return (skHandle, pkBytes);
            }, ex => EcliptixProtocolFailure.KeyGeneration("Failed to generate Ed25519 key pair.", ex));
        }
        finally
        {
            if (skBytes != null) SodiumInterop.SecureWipe(skBytes).IgnoreResult();
        }
    }

    private static Result<(SodiumSecureMemoryHandle skHandle, byte[] pk), EcliptixProtocolFailure>
        GenerateX25519IdentityKeys()
    {
        return SodiumInterop.GenerateX25519KeyPair("Identity");
    }

    private static Result<(SodiumSecureMemoryHandle skHandle, byte[] pk), EcliptixProtocolFailure>
        GenerateX25519SignedPreKey(uint id)
    {
        return SodiumInterop.GenerateX25519KeyPair($"Signed PreKey (ID: {id})");
    }

    private static Result<byte[], EcliptixProtocolFailure> SignSignedPreKey(SodiumSecureMemoryHandle edSkHandle,
        byte[] spkPk)
    {
        byte[]? tempEdSignKeyCopy = null;
        try
        {
            Result<byte[], EcliptixProtocolFailure> readResult = edSkHandle.ReadBytes(Constants.Ed25519SecretKeySize).MapSodiumFailure();
            if (readResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(readResult.UnwrapErr());
            tempEdSignKeyCopy = readResult.Unwrap();

            Result<byte[], EcliptixProtocolFailure> signResult = Result<byte[], EcliptixProtocolFailure>.Try(
                () => PublicKeyAuth.SignDetached(spkPk, tempEdSignKeyCopy),
                ex => EcliptixProtocolFailure.Generic("Failed to sign signed prekey public key.", ex));

            if (signResult.IsErr) return signResult;

            byte[] signature = signResult.Unwrap();
            if (signature.Length != Constants.Ed25519SignatureSize)
            {
                SodiumInterop.SecureWipe(signature).IgnoreResult();
                return Result<byte[], EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic(
                        $"Generated SPK signature has incorrect size ({signature.Length})."));
            }

            return Result<byte[], EcliptixProtocolFailure>.Ok(signature);
        }
        finally
        {
            if (tempEdSignKeyCopy != null) SodiumInterop.SecureWipe(tempEdSignKeyCopy).IgnoreResult();
        }
    }

    private static Result<List<OneTimePreKeyLocal>, EcliptixProtocolFailure> GenerateOneTimePreKeys(uint count)
    {
        if (count == 0)
            return Result<List<OneTimePreKeyLocal>, EcliptixProtocolFailure>.Ok(new List<OneTimePreKeyLocal>());

        List<OneTimePreKeyLocal> opks = new((int)count);
        HashSet<uint> usedIds = new((int)count);
        uint idCounter = 2;

        try
        {
            for (int i = 0; i < count; i++)
            {
                uint id = idCounter++;
                while (usedIds.Contains(id)) id = GenerateRandomUInt32();
                usedIds.Add(id);

                Result<OneTimePreKeyLocal, EcliptixProtocolFailure> opkResult = OneTimePreKeyLocal.Generate(id);
                if (opkResult.IsErr)
                {
                    foreach (OneTimePreKeyLocal generatedOpk in opks) generatedOpk.Dispose();
                    return Result<List<OneTimePreKeyLocal>, EcliptixProtocolFailure>.Err(opkResult.UnwrapErr());
                }

                opks.Add(opkResult.Unwrap());
            }

            return Result<List<OneTimePreKeyLocal>, EcliptixProtocolFailure>.Ok(opks);
        }
        catch (Exception ex)
        {
            foreach (OneTimePreKeyLocal generatedOpk in opks) generatedOpk.Dispose();
            return Result<List<OneTimePreKeyLocal>, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration("Unexpected error generating one-time prekeys.", ex));
        }
    }

    private static uint GenerateRandomUInt32()
    {
        byte[] buffer = SodiumCore.GetRandomBytes(sizeof(uint));
        return BitConverter.ToUInt32(buffer, 0);
    }

    public Result<PublicKeyBundle, EcliptixProtocolFailure> CreatePublicBundle()
    {
        if (_disposed)
            return Result<PublicKeyBundle, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(EcliptixSystemIdentityKeys)));

        return Result<PublicKeyBundle, EcliptixProtocolFailure>.Try(() =>
        {
            List<OneTimePreKeyRecord> opkRecords = _oneTimePreKeysInternal
                .Select(opkLocal => new OneTimePreKeyRecord(opkLocal.PreKeyId, opkLocal.PublicKey)).ToList();

            return new PublicKeyBundle(
                _ed25519PublicKey,
                IdentityX25519PublicKey,
                _signedPreKeyId,
                _signedPreKeyPublic,
                _signedPreKeySignature,
                opkRecords,
                _ephemeralX25519PublicKey);
        }, ex => EcliptixProtocolFailure.Generic("Failed to create public key bundle.", ex));
    }

    public void GenerateEphemeralKeyPair()
    {
        if (_disposed)
        {
            Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(EcliptixSystemIdentityKeys)));
            return;
        }

        _ephemeralSecretKeyHandle?.Dispose();
        if (_ephemeralX25519PublicKey != null) SodiumInterop.SecureWipe(_ephemeralX25519PublicKey).IgnoreResult();

        Result<(SodiumSecureMemoryHandle skHandle, byte[] pk), EcliptixProtocolFailure> generationResult =
            SodiumInterop.GenerateX25519KeyPair("Ephemeral");
        generationResult.Switch(
            keys =>
            {
                _ephemeralSecretKeyHandle = keys.skHandle;
                _ephemeralX25519PublicKey = keys.pk;
            },
            _ =>
            {
                _ephemeralSecretKeyHandle = null;
                _ephemeralX25519PublicKey = null;
            });
    }

    public Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure> X3dhDeriveSharedSecret(
        PublicKeyBundle remoteBundle, ReadOnlySpan<byte> info)
    {
        SodiumSecureMemoryHandle? ephemeralHandleUsed = null;
        SodiumSecureMemoryHandle? secureOutputHandle = null;
        byte[]? ephemeralSecretBytes = null,
            identitySecretBytes = null,
            dh1 = null,
            dh2 = null,
            dh3 = null,
            dh4 = null,
            ikmBytes = null;
        byte[]? dhConcatBytes = null, hkdfOutput = null;

        try
        {
            Result<Unit, EcliptixProtocolFailure> hkdfInfoValidationResult = ValidateHkdfInfo(info);
            if (hkdfInfoValidationResult.IsErr)
                return Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure>.Err(
                    hkdfInfoValidationResult.UnwrapErr());

            Result<Unit, EcliptixProtocolFailure> validationResult = CheckDisposed()
                .Bind(_ => ValidateRemoteBundle(remoteBundle))
                .Bind(_ => EnsureLocalKeysValid());

            if (validationResult.IsErr)
                return Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure>.Err(validationResult.UnwrapErr());

            Result<byte[], EcliptixProtocolFailure> readEphResult =
                _ephemeralSecretKeyHandle!.ReadBytes(Constants.X25519PrivateKeySize).MapSodiumFailure();
            if (readEphResult.IsErr)
                return Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure>.Err(readEphResult.UnwrapErr());
            ephemeralSecretBytes = readEphResult.Unwrap();

            Result<byte[], EcliptixProtocolFailure> readIdResult = _identityX25519SecretKeyHandle!
                .ReadBytes(Constants.X25519PrivateKeySize)
                .MapSodiumFailure();
            if (readIdResult.IsErr)
                return Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure>.Err(readIdResult.UnwrapErr());
            identitySecretBytes = readIdResult.Unwrap();

            ephemeralHandleUsed = _ephemeralSecretKeyHandle;
            _ephemeralSecretKeyHandle = null;

            bool useOpk = remoteBundle.OneTimePreKeys.FirstOrDefault()?.PublicKey is
                { Length: Constants.X25519PublicKeySize };
            dh1 = ScalarMult.Mult(ephemeralSecretBytes, remoteBundle.IdentityX25519);
            dh2 = ScalarMult.Mult(ephemeralSecretBytes, remoteBundle.SignedPreKeyPublic);
            dh3 = ScalarMult.Mult(identitySecretBytes, remoteBundle.SignedPreKeyPublic);
            if (useOpk)
            {
                dh4 = ScalarMult.Mult(ephemeralSecretBytes, remoteBundle.OneTimePreKeys[0].PublicKey);
            }

            int totalDhLength = Constants.X25519KeySize * (useOpk ? 4 : 3);
            dhConcatBytes = ArrayPool<byte>.Shared.Rent(totalDhLength);
            Span<byte> dhConcatSpan = dhConcatBytes.AsSpan(0, totalDhLength);
            ConcatenateDhResults(dhConcatSpan, dh1, dh2, dh3, dh4);

            Span<byte> f32 = stackalloc byte[Constants.X25519KeySize];
            f32.Fill(0xFF);
            ikmBytes = new byte[f32.Length + totalDhLength];
            f32.CopyTo(ikmBytes);
            dhConcatSpan.CopyTo(ikmBytes.AsSpan(f32.Length));

            hkdfOutput = ArrayPool<byte>.Shared.Rent(Constants.X25519KeySize);
            Span<byte> hkdfOutputSpan = hkdfOutput.AsSpan(0, Constants.X25519KeySize);

            using (HkdfSha256 hkdf = new(ikmBytes, salt: null))
            {
                hkdf.Expand(info.ToArray(), hkdfOutputSpan);
            }

            Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure> allocResult =
                SodiumSecureMemoryHandle.Allocate(Constants.X25519KeySize).MapSodiumFailure();
            if (allocResult.IsErr)
                return Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure>.Err(allocResult.UnwrapErr());

            secureOutputHandle = allocResult.Unwrap();
            Result<Unit, EcliptixProtocolFailure> writeResult =
                secureOutputHandle.Write(hkdfOutputSpan).MapSodiumFailure();
            if (writeResult.IsErr)
                return Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure>.Err(writeResult.UnwrapErr());

            SodiumSecureMemoryHandle returnHandle = secureOutputHandle;
            secureOutputHandle = null;
            return Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure>.Ok(returnHandle);
        }
        catch (Exception ex)
        {
            return Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.DeriveKey("An unexpected error occurred during X3DH shared secret derivation.",
                    ex));
        }
        finally
        {
            ephemeralHandleUsed?.Dispose();
            secureOutputHandle?.Dispose();
            if (ephemeralSecretBytes != null) SodiumInterop.SecureWipe(ephemeralSecretBytes).IgnoreResult();
            if (identitySecretBytes != null) SodiumInterop.SecureWipe(identitySecretBytes).IgnoreResult();
            if (dh1 != null) SodiumInterop.SecureWipe(dh1).IgnoreResult();
            if (dh2 != null) SodiumInterop.SecureWipe(dh2).IgnoreResult();
            if (dh3 != null) SodiumInterop.SecureWipe(dh3).IgnoreResult();
            if (dh4 != null) SodiumInterop.SecureWipe(dh4).IgnoreResult();
            if (ikmBytes != null) SodiumInterop.SecureWipe(ikmBytes).IgnoreResult();
            if (dhConcatBytes != null) ArrayPool<byte>.Shared.Return(dhConcatBytes, clearArray: true);
            if (hkdfOutput != null) ArrayPool<byte>.Shared.Return(hkdfOutput, clearArray: true);
        }
    }

    public Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure> CalculateSharedSecretAsRecipient(
        ReadOnlySpan<byte> remoteIdentityPublicKeyX, ReadOnlySpan<byte> remoteEphemeralPublicKeyX,
        uint? usedLocalOpkId, ReadOnlySpan<byte> info)
    {
        SodiumSecureMemoryHandle? secureOutputHandle = null;
        byte[]? identitySecretBytes = null, signedPreKeySecretBytes = null, oneTimePreKeySecretBytes = null;
        byte[]? dh1 = null, dh2 = null, dh3 = null, dh4 = null, ikmBytes = null;
        byte[]? dhConcatBytes = null, hkdfOutput = null;
        SodiumSecureMemoryHandle? opkSecretHandle = null;

        try
        {
            Result<Unit, EcliptixProtocolFailure> hkdfInfoValidationResult = ValidateHkdfInfo(info);
            if (hkdfInfoValidationResult.IsErr)
                return Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure>.Err(
                    hkdfInfoValidationResult.UnwrapErr());

            Result<Unit, EcliptixProtocolFailure> remoteRecipientKeysValidationResult =
                ValidateRemoteRecipientKeys(remoteIdentityPublicKeyX, remoteEphemeralPublicKeyX);
            if (remoteRecipientKeysValidationResult.IsErr)
                return Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure>.Err(
                    remoteRecipientKeysValidationResult.UnwrapErr());

            Result<Unit, EcliptixProtocolFailure> validationResult = CheckDisposed()
                .Bind(_ => EnsureLocalRecipientKeysValid());

            if (validationResult.IsErr)
                return Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure>.Err(validationResult.UnwrapErr());

            if (usedLocalOpkId.HasValue)
            {
                Result<SodiumSecureMemoryHandle?, EcliptixProtocolFailure> findOpkResult =
                    FindLocalOpkHandle(usedLocalOpkId.Value);
                if (findOpkResult.IsErr)
                    return Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure>.Err(findOpkResult.UnwrapErr());
                opkSecretHandle = findOpkResult.Unwrap();
            }

            Result<byte[], EcliptixProtocolFailure> readIdResult = _identityX25519SecretKeyHandle
                .ReadBytes(Constants.X25519PrivateKeySize)
                .MapSodiumFailure();
            if (readIdResult.IsErr)
                return Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure>.Err(readIdResult.UnwrapErr());
            identitySecretBytes = readIdResult.Unwrap();

            Result<byte[], EcliptixProtocolFailure> readSpkResult = _signedPreKeySecretKeyHandle
                .ReadBytes(Constants.X25519PrivateKeySize)
                .MapSodiumFailure();
            if (readSpkResult.IsErr)
                return Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure>.Err(readSpkResult.UnwrapErr());
            signedPreKeySecretBytes = readSpkResult.Unwrap();

            if (opkSecretHandle != null)
            {
                Result<byte[], EcliptixProtocolFailure> readOpkResult =
                    opkSecretHandle.ReadBytes(Constants.X25519PrivateKeySize).MapSodiumFailure();
                if (readOpkResult.IsErr)
                    return Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure>.Err(readOpkResult.UnwrapErr());
                oneTimePreKeySecretBytes = readOpkResult.Unwrap();
            }

            dh1 = ScalarMult.Mult(identitySecretBytes, remoteEphemeralPublicKeyX.ToArray());
            dh2 = ScalarMult.Mult(signedPreKeySecretBytes, remoteEphemeralPublicKeyX.ToArray());
            dh3 = ScalarMult.Mult(signedPreKeySecretBytes, remoteIdentityPublicKeyX.ToArray());
            if (oneTimePreKeySecretBytes != null)
                dh4 = ScalarMult.Mult(oneTimePreKeySecretBytes, remoteEphemeralPublicKeyX.ToArray());

            int totalDhLength = Constants.X25519KeySize * 3 +
                                (oneTimePreKeySecretBytes != null ? Constants.X25519KeySize : 0);
            dhConcatBytes = ArrayPool<byte>.Shared.Rent(totalDhLength);
            Span<byte> dhConcatSpan = dhConcatBytes.AsSpan(0, totalDhLength);
            ConcatenateDhResults(dhConcatSpan, dh1, dh2, dh3, dh4);

            Span<byte> f32 = stackalloc byte[Constants.X25519KeySize];
            f32.Fill(0xFF);
            ikmBytes = new byte[f32.Length + totalDhLength];
            f32.CopyTo(ikmBytes);
            dhConcatSpan.CopyTo(ikmBytes.AsSpan(f32.Length));

            hkdfOutput = ArrayPool<byte>.Shared.Rent(Constants.X25519KeySize);
            Span<byte> hkdfOutputSpan = hkdfOutput.AsSpan(0, Constants.X25519KeySize);

            using (HkdfSha256 hkdf = new(ikmBytes, salt: null))
            {
                hkdf.Expand(info.ToArray(), hkdfOutputSpan);
            }

            Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure> allocResult =
                SodiumSecureMemoryHandle.Allocate(Constants.X25519KeySize).MapSodiumFailure();
            if (allocResult.IsErr)
                return Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure>.Err(allocResult.UnwrapErr());

            secureOutputHandle = allocResult.Unwrap();
            Result<Unit, EcliptixProtocolFailure> writeResult =
                secureOutputHandle.Write(hkdfOutputSpan).MapSodiumFailure();
            if (writeResult.IsErr)
                return Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure>.Err(writeResult.UnwrapErr());

            SodiumSecureMemoryHandle returnHandle = secureOutputHandle;
            secureOutputHandle = null;
            return Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure>.Ok(returnHandle);
        }
        catch (Exception ex)
        {
            return Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.DeriveKey(
                    "An unexpected error occurred during Recipient shared secret derivation.", ex));
        }
        finally
        {
            secureOutputHandle?.Dispose();
            if (identitySecretBytes != null) SodiumInterop.SecureWipe(identitySecretBytes).IgnoreResult();
            if (signedPreKeySecretBytes != null) SodiumInterop.SecureWipe(signedPreKeySecretBytes).IgnoreResult();
            if (oneTimePreKeySecretBytes != null) SodiumInterop.SecureWipe(oneTimePreKeySecretBytes).IgnoreResult();
            if (dh1 != null) SodiumInterop.SecureWipe(dh1).IgnoreResult();
            if (dh2 != null) SodiumInterop.SecureWipe(dh2).IgnoreResult();
            if (dh3 != null) SodiumInterop.SecureWipe(dh3).IgnoreResult();
            if (dh4 != null) SodiumInterop.SecureWipe(dh4).IgnoreResult();
            if (ikmBytes != null) SodiumInterop.SecureWipe(ikmBytes).IgnoreResult();
            if (dhConcatBytes != null) ArrayPool<byte>.Shared.Return(dhConcatBytes, clearArray: true);
            if (hkdfOutput != null) ArrayPool<byte>.Shared.Return(hkdfOutput, clearArray: true);
        }
    }

    public static Result<bool, EcliptixProtocolFailure> VerifyRemoteSpkSignature(
        ReadOnlySpan<byte> remoteIdentityEd25519, ReadOnlySpan<byte> remoteSpkPublic,
        ReadOnlySpan<byte> remoteSpkSignature)
    {
        if (remoteIdentityEd25519.Length != Constants.Ed25519PublicKeySize ||
            remoteSpkPublic.Length != Constants.X25519PublicKeySize ||
            remoteSpkSignature.Length != Constants.Ed25519SignatureSize)
        {
            return Result<bool, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Invalid key or signature length for SPK verification."));
        }

        bool verificationResult = PublicKeyAuth.VerifyDetached(remoteSpkSignature.ToArray(), remoteSpkPublic.ToArray(),
            remoteIdentityEd25519.ToArray());

        return verificationResult
            ? Result<bool, EcliptixProtocolFailure>.Ok(true)
            : Result<bool, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Handshake("Remote SPK signature verification failed."));
    }

    private Result<Unit, EcliptixProtocolFailure> CheckDisposed()
    {
        return _disposed
            ? Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(EcliptixSystemIdentityKeys)))
            : Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    private static Result<Unit, EcliptixProtocolFailure> ValidateHkdfInfo(ReadOnlySpan<byte> info)
    {
        return info.IsEmpty
            ? Result<Unit, EcliptixProtocolFailure>.Err(EcliptixProtocolFailure.DeriveKey("HKDF info cannot be empty."))
            : Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    private static Result<Unit, EcliptixProtocolFailure> ValidateRemoteBundle(PublicKeyBundle? remoteBundle)
    {
        if (remoteBundle == null)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Remote bundle cannot be null."));

        if (remoteBundle.IdentityX25519 is not { Length: Constants.X25519PublicKeySize })
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.PeerPubKey("Invalid remote IdentityX25519 key."));

        if (remoteBundle.SignedPreKeyPublic is not { Length: Constants.X25519PublicKeySize })
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.PeerPubKey("Invalid remote SignedPreKeyPublic key."));

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    private Result<Unit, EcliptixProtocolFailure> EnsureLocalKeysValid()
    {
        if (_ephemeralSecretKeyHandle == null || _ephemeralSecretKeyHandle.IsInvalid)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.PrepareLocal("Local ephemeral key is missing or invalid."));

        if (_identityX25519SecretKeyHandle.IsInvalid)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.PrepareLocal("Local identity key is missing or invalid."));

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    private static Result<Unit, EcliptixProtocolFailure> ValidateRemoteRecipientKeys(
        ReadOnlySpan<byte> remoteIdentityPublicKeyX, ReadOnlySpan<byte> remoteEphemeralPublicKeyX)
    {
        if (remoteIdentityPublicKeyX.Length != Constants.X25519PublicKeySize)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.PeerPubKey("Invalid remote Identity key length."));

        if (remoteEphemeralPublicKeyX.Length != Constants.X25519PublicKeySize)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.PeerPubKey("Invalid remote Ephemeral key length."));

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    private Result<Unit, EcliptixProtocolFailure> EnsureLocalRecipientKeysValid()
    {
        if (_identityX25519SecretKeyHandle.IsInvalid)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.PrepareLocal("Local identity key is missing or invalid."));

        if (_signedPreKeySecretKeyHandle.IsInvalid)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.PrepareLocal("Local signed prekey is missing or invalid."));

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    private Result<SodiumSecureMemoryHandle?, EcliptixProtocolFailure> FindLocalOpkHandle(uint opkId)
    {
        foreach (OneTimePreKeyLocal opk in _oneTimePreKeysInternal.Where(opk => opk.PreKeyId == opkId))
        {
            if (opk.PrivateKeyHandle.IsInvalid)
                return Result<SodiumSecureMemoryHandle?, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.PrepareLocal($"Local OPK ID {opkId} found but its handle is invalid."));
            return Result<SodiumSecureMemoryHandle?, EcliptixProtocolFailure>.Ok(opk.PrivateKeyHandle);
        }

        return Result<SodiumSecureMemoryHandle?, EcliptixProtocolFailure>.Err(
            EcliptixProtocolFailure.Handshake($"Local OPK ID {opkId} not found."));
    }

    private static void ConcatenateDhResults(Span<byte> destination, byte[] dh1, byte[] dh2, byte[] dh3, byte[]? dh4)
    {
        int offset = 0;
        dh1.AsSpan(0, Constants.X25519KeySize).CopyTo(destination.Slice(offset));
        offset += Constants.X25519KeySize;
        dh2.AsSpan(0, Constants.X25519KeySize).CopyTo(destination.Slice(offset));
        offset += Constants.X25519KeySize;
        dh3.AsSpan(0, Constants.X25519KeySize).CopyTo(destination.Slice(offset));
        if (dh4 != null)
        {
            offset += Constants.X25519KeySize;
            dh4.AsSpan(0, Constants.X25519KeySize).CopyTo(destination.Slice(offset));
        }
    }

    private void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing) SecureCleanupLogic();
            _disposed = true;
        }
    }

    private void SecureCleanupLogic()
    {
        _ed25519SecretKeyHandle?.Dispose();
        _identityX25519SecretKeyHandle?.Dispose();
        _signedPreKeySecretKeyHandle?.Dispose();
        _ephemeralSecretKeyHandle?.Dispose();
        foreach (OneTimePreKeyLocal opk in _oneTimePreKeysInternal) opk.Dispose();
        _oneTimePreKeysInternal.Clear();
        _oneTimePreKeysInternal = null!;

        _ephemeralSecretKeyHandle = null;
    }

    ~EcliptixSystemIdentityKeys()
    {
        Dispose(false);
    }
}