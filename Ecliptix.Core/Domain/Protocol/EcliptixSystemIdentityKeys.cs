using System.Buffers;
using Ecliptix.Core.Domain.Protocol;
using Ecliptix.Core.Domain.Protocol.Failures;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.ProtocolState;
using Google.Protobuf;
using Serilog;
using Serilog.Events;
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

    private volatile IdentityKeysState? _cachedProtoState;
    private volatile int _lastOpkCount = -1;
    private readonly Lock _cacheUpdateLock = new();

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
    }

    public Result<IdentityKeysState, EcliptixProtocolFailure> ToProtoState()
    {
        if (_disposed)
            return Result<IdentityKeysState, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ObjectDisposed(nameof(EcliptixSystemIdentityKeys)));

        IdentityKeysState? cachedState = _cachedProtoState;
        if (cachedState != null && _lastOpkCount == _oneTimePreKeysInternal.Count)
        {
            return Result<IdentityKeysState, EcliptixProtocolFailure>.Ok(cachedState);
        }

        lock (_cacheUpdateLock)
        {
            cachedState = _cachedProtoState;
            if (cachedState != null && _lastOpkCount == _oneTimePreKeysInternal.Count)
            {
                return Result<IdentityKeysState, EcliptixProtocolFailure>.Ok(cachedState);
            }

            return BuildAndCacheProtoState();
        }
    }

    private Result<IdentityKeysState, EcliptixProtocolFailure> BuildAndCacheProtoState()
    {
        byte[]? edSk = null;
        byte[]? idSk = null;
        byte[]? spkSk = null;
        try
        {
            edSk = _ed25519SecretKeyHandle.ReadBytes(Constants.Ed25519SecretKeySize).Unwrap();
            idSk = _identityX25519SecretKeyHandle.ReadBytes(Constants.X25519PrivateKeySize).Unwrap();
            spkSk = _signedPreKeySecretKeyHandle.ReadBytes(Constants.X25519PrivateKeySize).Unwrap();

            List<OneTimePreKeySecret> opkProtos = [];
            foreach (OneTimePreKeyLocal opk in _oneTimePreKeysInternal)
            {
                byte[] opkSkBytes = opk.PrivateKeyHandle.ReadBytes(Constants.X25519PrivateKeySize).Unwrap();
                opkProtos.Add(new OneTimePreKeySecret
                {
                    PreKeyId = opk.PreKeyId,
                    PrivateKey = ByteString.CopyFrom(opkSkBytes.AsSpan()),
                    PublicKey = ByteString.CopyFrom(opk.PublicKey.AsSpan())
                });
                SodiumInterop.SecureWipe(opkSkBytes).IgnoreResult();
            }

            IdentityKeysState proto = new()
            {
                Ed25519SecretKey = ByteString.CopyFrom(edSk.AsSpan()),
                IdentityX25519SecretKey = ByteString.CopyFrom(idSk.AsSpan()),
                SignedPreKeySecret = ByteString.CopyFrom(spkSk.AsSpan()),
                Ed25519PublicKey = ByteString.CopyFrom(_ed25519PublicKey.AsSpan()),
                IdentityX25519PublicKey = ByteString.CopyFrom(IdentityX25519PublicKey.AsSpan()),
                SignedPreKeyId = _signedPreKeyId,
                SignedPreKeyPublic = ByteString.CopyFrom(_signedPreKeyPublic.AsSpan()),
                SignedPreKeySignature = ByteString.CopyFrom(_signedPreKeySignature.AsSpan())
            };
            proto.OneTimePreKeys.AddRange(opkProtos);

            if (Log.IsEnabled(LogEventLevel.Debug))
            {
                Log.Debug("[EcliptixSystemIdentityKeys] Exporting to Proto State:");
                Log.Debug("  Ed25519 Public Key: {EdPk}", Convert.ToHexString(_ed25519PublicKey));
                Log.Debug("  Identity X25519 Public Key: {IdPk}", Convert.ToHexString(IdentityX25519PublicKey));
                Log.Debug("  Signed PreKey ID: {SpkId}", _signedPreKeyId);
                Log.Debug("  Signed PreKey Public Key: {SpkPk}", Convert.ToHexString(_signedPreKeyPublic));
                Log.Debug("  Signed PreKey Signature: {SpkSig}", Convert.ToHexString(_signedPreKeySignature));
                Log.Debug("  One-Time PreKeys (Count: {Count}):", opkProtos.Count);
                foreach (OneTimePreKeySecret opk in opkProtos)
                {
                    Log.Debug(
                        "    ID {Id}: Public Key: {Pub}",
                        opk.PreKeyId,
                        Convert.ToHexString(opk.PublicKey.Span));
                }
            }

            _cachedProtoState = proto;
            _lastOpkCount = _oneTimePreKeysInternal.Count;

            return Result<IdentityKeysState, EcliptixProtocolFailure>.Ok(proto);
        }
        catch (Exception ex)
        {
            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixSystemIdentityKeys] Error exporting to proto state: {Message}", ex.Message);
            return Result<IdentityKeysState, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Failed to export identity keys to proto state.", ex));
        }
        finally
        {
            SodiumInterop.SecureWipe(edSk).IgnoreResult();
            SodiumInterop.SecureWipe(idSk).IgnoreResult();
            SodiumInterop.SecureWipe(spkSk).IgnoreResult();
        }
    }

    public static Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> FromProtoState(IdentityKeysState proto)
    {
        if (proto == null)
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Proto state is null."));

        if (proto.Ed25519SecretKey == null || proto.Ed25519SecretKey.IsEmpty)
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Ed25519 secret key is null or empty."));

        if (proto.IdentityX25519SecretKey == null || proto.IdentityX25519SecretKey.IsEmpty)
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Identity X25519 secret key is null or empty."));

        if (proto.SignedPreKeySecret == null || proto.SignedPreKeySecret.IsEmpty)
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Signed prekey secret is null or empty."));

        if (proto.Ed25519PublicKey == null || proto.Ed25519PublicKey.IsEmpty)
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Ed25519 public key is null or empty."));

        if (proto.IdentityX25519PublicKey == null || proto.IdentityX25519PublicKey.IsEmpty)
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Identity X25519 public key is null or empty."));

        if (proto.SignedPreKeyPublic == null || proto.SignedPreKeyPublic.IsEmpty)
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Signed prekey public key is null or empty."));

        if (proto.SignedPreKeySignature == null || proto.SignedPreKeySignature.IsEmpty)
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Signed prekey signature is null or empty."));

        SodiumSecureMemoryHandle? edSkHandle = null;
        SodiumSecureMemoryHandle? idXSkHandle = null;
        SodiumSecureMemoryHandle? spkSkHandle = null;
        List<OneTimePreKeyLocal>? opks = null;

        try
        {
            ReadOnlySpan<byte> edSkSpan = proto.Ed25519SecretKey.Span;
            if (edSkSpan.Length != Constants.Ed25519SecretKeySize)
                return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.InvalidInput("Invalid Ed25519 secret key length."));
            edSkHandle = SodiumSecureMemoryHandle.Allocate(edSkSpan.Length).Unwrap();
            edSkHandle.Write(edSkSpan).Unwrap();

            ReadOnlySpan<byte> idSkSpan = proto.IdentityX25519SecretKey.Span;
            if (idSkSpan.Length != Constants.X25519PrivateKeySize)
                return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.InvalidInput("Invalid X25519 identity secret key length."));
            idXSkHandle = SodiumSecureMemoryHandle.Allocate(idSkSpan.Length).Unwrap();
            idXSkHandle.Write(idSkSpan).Unwrap();

            ReadOnlySpan<byte> spkSkSpan = proto.SignedPreKeySecret.Span;
            if (spkSkSpan.Length != Constants.X25519PrivateKeySize)
                return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.InvalidInput("Invalid signed prekey secret key length."));
            spkSkHandle = SodiumSecureMemoryHandle.Allocate(spkSkSpan.Length).Unwrap();
            spkSkHandle.Write(spkSkSpan).Unwrap();

            ReadOnlySpan<byte> edPkSpan = proto.Ed25519PublicKey.Span;
            if (edPkSpan.Length != Constants.Ed25519PublicKeySize)
                return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.InvalidInput("Invalid Ed25519 public key length."));
            byte[] edPk = new byte[edPkSpan.Length];
            edPkSpan.CopyTo(edPk);

            ReadOnlySpan<byte> idXPkSpan = proto.IdentityX25519PublicKey.Span;
            if (idXPkSpan.Length != Constants.X25519PublicKeySize)
                return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.InvalidInput("Invalid X25519 identity public key length."));
            byte[] idXPk = new byte[idXPkSpan.Length];
            idXPkSpan.CopyTo(idXPk);

            ReadOnlySpan<byte> spkPkSpan = proto.SignedPreKeyPublic.Span;
            if (spkPkSpan.Length != Constants.X25519PublicKeySize)
                return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.InvalidInput("Invalid signed prekey public key length."));
            byte[] spkPk = new byte[spkPkSpan.Length];
            spkPkSpan.CopyTo(spkPk);

            ReadOnlySpan<byte> spkSigSpan = proto.SignedPreKeySignature.Span;
            if (spkSigSpan.Length != Constants.Ed25519SignatureSize)
                return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.InvalidInput("Invalid signed prekey signature length."));
            byte[] spkSig = new byte[spkSigSpan.Length];
            spkSigSpan.CopyTo(spkSig);

            opks = [];
            if (proto.OneTimePreKeys != null)
            {
                foreach (OneTimePreKeySecret opkProto in proto.OneTimePreKeys)
                {
                    if (opkProto?.PrivateKey == null || opkProto.PrivateKey.IsEmpty)
                        return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(
                            EcliptixProtocolFailure.InvalidInput(
                                $"OPK private key is null or empty for ID {opkProto?.PreKeyId}."));

                    if (opkProto?.PublicKey == null || opkProto.PublicKey.IsEmpty)
                        return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(
                            EcliptixProtocolFailure.InvalidInput(
                                $"OPK public key is null or empty for ID {opkProto?.PreKeyId}."));

                    ReadOnlySpan<byte> opkSkSpan = opkProto.PrivateKey.Span;
                    if (opkSkSpan.Length != Constants.X25519PrivateKeySize)
                        return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(
                            EcliptixProtocolFailure.InvalidInput(
                                $"Invalid OPK secret key length for ID {opkProto.PreKeyId}."));

                    ReadOnlySpan<byte> opkPkSpan = opkProto.PublicKey.Span;
                if (opkPkSpan.Length != Constants.X25519PublicKeySize)
                    return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.InvalidInput(
                            $"Invalid OPK public key length for ID {opkProto.PreKeyId}."));

                SodiumSecureMemoryHandle skHandle = SodiumSecureMemoryHandle.Allocate(opkSkSpan.Length).Unwrap();
                skHandle.Write(opkSkSpan).Unwrap();

                    byte[] opkPkBytes = new byte[opkPkSpan.Length];
                    opkPkSpan.CopyTo(opkPkBytes);
                    OneTimePreKeyLocal opk = OneTimePreKeyLocal.CreateFromParts(opkProto.PreKeyId, skHandle, opkPkBytes);
                    opks.Add(opk);
                }
            }

            if (Log.IsEnabled(LogEventLevel.Debug))
            {
                Log.Debug("[EcliptixSystemIdentityKeys] Restored from Proto State:");
                Log.Debug("  Ed25519 Public Key: {EdPk}", Convert.ToHexString(edPk));
                Log.Debug("  Identity X25519 Public Key: {IdPk}", Convert.ToHexString(idXPk));
                Log.Debug("  Signed PreKey ID: {SpkId}", proto.SignedPreKeyId);
                Log.Debug("  Signed PreKey Public Key: {SpkPk}", Convert.ToHexString(spkPk));
                Log.Debug("  Signed PreKey Signature: {SpkSig}", Convert.ToHexString(spkSig));
                Log.Debug("  One-Time PreKeys (Count: {Count}):", opks.Count);
                foreach (OneTimePreKeyLocal opk in opks)
                {
                    Log.Debug(
                        "    ID {Id}: Public Key: {Pub}",
                        opk.PreKeyId,
                        Convert.ToHexString(opk.PublicKey));
                }
            }

            EcliptixSystemIdentityKeys keys = new(
                edSkHandle, edPk,
                idXSkHandle, idXPk,
                proto.SignedPreKeyId, spkSkHandle, spkPk, spkSig,
                opks);

            edSkHandle = null;
            idXSkHandle = null;
            spkSkHandle = null;
            opks = null;

            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Ok(keys);
        }
        catch (Exception ex)
        {
            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixSystemIdentityKeys] Error restoring from proto state: {Message}", ex.Message);
            edSkHandle?.Dispose();
            idXSkHandle?.Dispose();
            spkSkHandle?.Dispose();
            if (opks != null)
            {
                foreach (OneTimePreKeyLocal k in opks) 
                {
                    k.Dispose();
                }
            }
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Failed to rehydrate EcliptixSystemIdentityKeys from proto.", ex));
        }
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
            Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure> edKeysResult = GenerateEd25519Keys();
            if (edKeysResult.IsErr)
            {
                return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(edKeysResult.UnwrapErr());
            }

            (edSkHandle, edPk) = edKeysResult.Unwrap();

            Span<byte> tempEdSk = stackalloc byte[Constants.Ed25519SecretKeySize];
            if (edSkHandle.Read(tempEdSk).IsOk)
            {
                if (Log.IsEnabled(LogEventLevel.Debug))
                    Log.Debug("[EcliptixSystemIdentityKeys] Generated Ed25519 Secret Key: {EdSk}",
                        Convert.ToHexString(tempEdSk));
            }

            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixSystemIdentityKeys] Generated Ed25519 Public Key: {EdPk}",
                    Convert.ToHexString(edPk));

            Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure> idKeysResult = GenerateX25519IdentityKeys();
            if (idKeysResult.IsErr)
            {
                edSkHandle?.Dispose();
                return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(idKeysResult.UnwrapErr());
            }

            (idXSkHandle, idXPk) = idKeysResult.Unwrap();

            Span<byte> tempIdSk = stackalloc byte[Constants.X25519PrivateKeySize];
            if (idXSkHandle.Read(tempIdSk).IsOk)
            {
                if (Log.IsEnabled(LogEventLevel.Debug))
                    Log.Debug("[EcliptixSystemIdentityKeys] Generated Identity X25519 Secret Key: {IdSk}",
                        Convert.ToHexString(tempIdSk));
            }

            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixSystemIdentityKeys] Generated Identity X25519 Public Key: {IdPk}",
                    Convert.ToHexString(idXPk));

            spkId = GenerateRandomUInt32();
            Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure> spkKeysResult = GenerateX25519SignedPreKey(spkId);
            if (spkKeysResult.IsErr)
            {
                edSkHandle?.Dispose();
                idXSkHandle?.Dispose();
                return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(spkKeysResult.UnwrapErr());
            }

            (spkSkHandle, spkPk) = spkKeysResult.Unwrap();

            Span<byte> tempSpkSk = stackalloc byte[Constants.X25519PrivateKeySize];
            if (spkSkHandle.Read(tempSpkSk).IsOk)
            {
                if (Log.IsEnabled(LogEventLevel.Debug))
                    Log.Debug(
                        "[EcliptixSystemIdentityKeys] Generated Signed PreKey Secret Key (ID: {SpkId}): {SpkSk}",
                        spkId, Convert.ToHexString(tempSpkSk));
            }

            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug(
                    "[EcliptixSystemIdentityKeys] Generated Signed PreKey Public Key (ID: {SpkId}): {SpkPk}",
                    spkId, Convert.ToHexString(spkPk));

            Result<byte[], EcliptixProtocolFailure> signatureResult = SignSignedPreKey(edSkHandle!, spkPk!);
            if (signatureResult.IsErr)
            {
                edSkHandle?.Dispose();
                idXSkHandle?.Dispose();
                spkSkHandle?.Dispose();
                return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(signatureResult.UnwrapErr());
            }

            spkSig = signatureResult.Unwrap();

            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixSystemIdentityKeys] Generated Signed PreKey Signature: {SpkSig}",
                    Convert.ToHexString(spkSig));

            Result<List<OneTimePreKeyLocal>, EcliptixProtocolFailure> opksResult = GenerateOneTimePreKeys(oneTimeKeyCount);
            if (opksResult.IsErr)
            {
                edSkHandle?.Dispose();
                idXSkHandle?.Dispose();
                spkSkHandle?.Dispose();
                return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(opksResult.UnwrapErr());
            }

            opks = opksResult.Unwrap();

            EcliptixSystemIdentityKeys material = new(edSkHandle!, edPk!, idXSkHandle!, idXPk!, spkId,
                spkSkHandle!, spkPk!, spkSig!, opks);

            edSkHandle = null;
            idXSkHandle = null;
            spkSkHandle = null;
            opks = null;

            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Ok(material);
        }
        catch (Exception ex)
        {
            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixSystemIdentityKeys] Error creating identity keys: {Message}", ex.Message);
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
        SodiumSecureMemoryHandle? skHandle;
        byte[]? skBytes = null;
        try
        {
            KeyPair edKeyPair = PublicKeyAuth.GenerateKeyPair();
            skBytes = edKeyPair.PrivateKey;
            byte[] pkBytes = edKeyPair.PublicKey;

            skHandle = SodiumSecureMemoryHandle.Allocate(Constants.Ed25519SecretKeySize).Unwrap();
            skHandle.Write(skBytes).Unwrap();

            return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Ok((skHandle, pkBytes));
        }
        catch (Exception ex)
        {
            return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration("Failed to generate Ed25519 key pair.", ex));
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
            Result<byte[], EcliptixProtocolFailure> readResult =
                edSkHandle.ReadBytes(Constants.Ed25519SecretKeySize).MapSodiumFailure();
            if (readResult.IsErr) return Result<byte[], EcliptixProtocolFailure>.Err(readResult.UnwrapErr());
            tempEdSignKeyCopy = readResult.Unwrap();

            byte[] signature;
            try
            {
                signature = PublicKeyAuth.SignDetached(spkPk, tempEdSignKeyCopy);
            }
            catch (Exception ex)
            {
                return Result<byte[], EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Failed to sign signed prekey public key.", ex));
            }
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
            Span<byte> tempOpkSk = stackalloc byte[Constants.X25519PrivateKeySize];
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

                OneTimePreKeyLocal opk = opkResult.Unwrap();

                if (opk.PrivateKeyHandle.Read(tempOpkSk).IsOk)
                {
                    if (Log.IsEnabled(LogEventLevel.Debug))
                        Log.Debug("[EcliptixSystemIdentityKeys] Generated One-Time PreKey ID {Id}: Private Key: {Priv}",
                            id, Convert.ToHexString(tempOpkSk));
                }

                if (Log.IsEnabled(LogEventLevel.Debug))
                    Log.Debug("[EcliptixSystemIdentityKeys] Generated One-Time PreKey ID {Id}: Public Key: {Pub}", id,
                        Convert.ToHexString(opk.PublicKey));
                opks.Add(opk);
            }

            return Result<List<OneTimePreKeyLocal>, EcliptixProtocolFailure>.Ok(opks);
        }
        catch (Exception ex)
        {
            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixSystemIdentityKeys] Error generating one-time prekeys: {exMessage}", ex.Message);

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

        try
        {
            List<OneTimePreKeyRecord> opkRecords = new();
            foreach (OneTimePreKeyLocal opkLocal in _oneTimePreKeysInternal)
            {
                opkRecords.Add(new OneTimePreKeyRecord(opkLocal.PreKeyId, opkLocal.PublicKey));
            }

            return Result<PublicKeyBundle, EcliptixProtocolFailure>.Ok(new PublicKeyBundle(
                _ed25519PublicKey,
                IdentityX25519PublicKey,
                _signedPreKeyId,
                _signedPreKeyPublic,
                _signedPreKeySignature,
                opkRecords,
                _ephemeralX25519PublicKey));
        }
        catch (Exception ex)
        {
            return Result<PublicKeyBundle, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Failed to create public key bundle.", ex));
        }
    }

    public void GenerateEphemeralKeyPair()
    {
        if (_disposed)
        {
            return;
        }

        _ephemeralSecretKeyHandle?.Dispose();
        if (_ephemeralX25519PublicKey != null) SodiumInterop.SecureWipe(_ephemeralX25519PublicKey).IgnoreResult();

        Result<(SodiumSecureMemoryHandle skHandle, byte[] pk), EcliptixProtocolFailure> generationResult =
            SodiumInterop.GenerateX25519KeyPair("Ephemeral");

        if (generationResult.IsOk)
        {
            (SodiumSecureMemoryHandle skHandle, byte[] pk) keys = generationResult.Unwrap();
            _ephemeralSecretKeyHandle = keys.skHandle;
            _ephemeralX25519PublicKey = keys.pk;

            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixSystemIdentityKeys] Generated Ephemeral X25519 Public Key: {EphPk}",
                    Convert.ToHexString(_ephemeralX25519PublicKey));
        }
        else
        {
            _ephemeralSecretKeyHandle = null;
            _ephemeralX25519PublicKey = null;
        }
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

            Result<Unit, EcliptixProtocolFailure> disposedCheckResult = CheckDisposed();
            if (disposedCheckResult.IsErr)
                return Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure>.Err(disposedCheckResult.UnwrapErr());

            Result<Unit, EcliptixProtocolFailure> bundleValidationResult = ValidateRemoteBundle(remoteBundle);
            if (bundleValidationResult.IsErr)
                return Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure>.Err(bundleValidationResult.UnwrapErr());

            Result<Unit, EcliptixProtocolFailure> localKeysValidationResult = EnsureLocalKeysValid();
            if (localKeysValidationResult.IsErr)
                return Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure>.Err(localKeysValidationResult.UnwrapErr());

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

            if (Log.IsEnabled(LogEventLevel.Debug))
            {
                Log.Debug("[EcliptixSystemIdentityKeys] X3DH DH Results:");
                Log.Debug("  DH1 (Ephemeral * Remote Identity): {Dh1}", Convert.ToHexString(dh1));
                Log.Debug("  DH2 (Ephemeral * Remote Signed PreKey): {Dh2}", Convert.ToHexString(dh2));
                Log.Debug("  DH3 (Identity * Remote Signed PreKey): {Dh3}", Convert.ToHexString(dh3));
                if (useOpk)
                {
                    Log.Debug("  DH4 (Ephemeral * Remote One-Time PreKey): {Dh4}", Convert.ToHexString(dh4!));
                }
            }

            int totalDhLength = Constants.X25519KeySize * (useOpk ? 4 : 3);
            dhConcatBytes = ArrayPool<byte>.Shared.Rent(totalDhLength);
            Span<byte> dhConcatSpan = dhConcatBytes.AsSpan(0, totalDhLength);
            ConcatenateDhResults(dhConcatSpan, dh3, dh1, dh2, dh4);

            Span<byte> f32 = stackalloc byte[Constants.X25519KeySize];
            f32.Fill(0xFF);
            int ikmSize = f32.Length + totalDhLength;
            ikmBytes = ArrayPool<byte>.Shared.Rent(ikmSize);
            Span<byte> ikmSpan = ikmBytes.AsSpan(0, ikmSize);
            f32.CopyTo(ikmSpan);
            dhConcatSpan.CopyTo(ikmSpan.Slice(f32.Length));
            byte[] actualIkmArray = ikmSpan.ToArray();

            hkdfOutput = ArrayPool<byte>.Shared.Rent(Constants.X25519KeySize);
            Span<byte> hkdfOutputSpan = hkdfOutput.AsSpan(0, Constants.X25519KeySize);

            try
            {
                System.Security.Cryptography.HKDF.DeriveKey(
                    System.Security.Cryptography.HashAlgorithmName.SHA256,
                    ikm: actualIkmArray,
                    output: hkdfOutputSpan,
                    salt: null,
                    info: info.ToArray()
                );

            }
            catch (Exception ex)
            {
                ArrayPool<byte>.Shared.Return(hkdfOutput);
                hkdfOutput = null;
                return Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.DeriveKey("HKDF failed during X3DH derivation.", ex));
            }

            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixSystemIdentityKeys] X3DH Shared Secret: {SharedSecret}",
                    Convert.ToHexString(hkdfOutputSpan.ToArray()));

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
            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixSystemIdentityKeys] Error deriving X3DH shared secret: {Message}", ex.Message);
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
            if (ikmBytes != null) ArrayPool<byte>.Shared.Return(ikmBytes, clearArray: true);
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

            if (Log.IsEnabled(LogEventLevel.Debug))
            {
                Log.Debug("[EcliptixSystemIdentityKeys] Recipient Shared Secret DH Results:");
                Log.Debug("  DH1 (Identity * Remote Ephemeral): {Dh1}", Convert.ToHexString(dh1));
                Log.Debug("  DH2 (Signed PreKey * Remote Ephemeral): {Dh2}", Convert.ToHexString(dh2));
                Log.Debug("  DH3 (Signed PreKey * Remote Identity): {Dh3}", Convert.ToHexString(dh3));
                if (oneTimePreKeySecretBytes != null)
                {
                    Log.Debug("  DH4 (One-Time PreKey * Remote Ephemeral): {Dh4}", Convert.ToHexString(dh4!));
                }
            }

            int totalDhLength = Constants.X25519KeySize * 3 +
                                (oneTimePreKeySecretBytes != null ? Constants.X25519KeySize : 0);
            dhConcatBytes = ArrayPool<byte>.Shared.Rent(totalDhLength);
            Span<byte> dhConcatSpan = dhConcatBytes.AsSpan(0, totalDhLength);
            ConcatenateDhResults(dhConcatSpan, dh3, dh1, dh2, dh4);

            Span<byte> f32 = stackalloc byte[Constants.X25519KeySize];
            f32.Fill(0xFF);
            int ikmSize = f32.Length + totalDhLength;
            ikmBytes = ArrayPool<byte>.Shared.Rent(ikmSize);
            Span<byte> ikmSpan = ikmBytes.AsSpan(0, ikmSize);
            f32.CopyTo(ikmSpan);
            dhConcatSpan.CopyTo(ikmSpan.Slice(f32.Length));
            byte[] actualIkmArray = ikmSpan.ToArray();

            hkdfOutput = ArrayPool<byte>.Shared.Rent(Constants.X25519KeySize);
            Span<byte> hkdfOutputSpan = hkdfOutput.AsSpan(0, Constants.X25519KeySize);

            try
            {
                System.Security.Cryptography.HKDF.DeriveKey(
                    System.Security.Cryptography.HashAlgorithmName.SHA256,
                    ikm: actualIkmArray,
                    output: hkdfOutputSpan,
                    salt: null,
                    info: info.ToArray()
                );

            }
            catch (Exception ex)
            {
                ArrayPool<byte>.Shared.Return(hkdfOutput);
                hkdfOutput = null;
                return Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.DeriveKey("HKDF failed during recipient X3DH derivation.", ex));
            }

            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixSystemIdentityKeys] Recipient Shared Secret: {SharedSecret}",
                    Convert.ToHexString(hkdfOutputSpan.ToArray()));

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
            if (Log.IsEnabled(LogEventLevel.Debug))
                Log.Debug("[EcliptixSystemIdentityKeys] Error deriving recipient shared secret: {Message}", ex.Message);
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
            if (ikmBytes != null) ArrayPool<byte>.Shared.Return(ikmBytes, clearArray: true);
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

        if (remoteBundle.IdentityX25519.Length != Constants.X25519PublicKeySize)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.PeerPubKey("Invalid remote IdentityX25519 key length."));

        if (remoteBundle.SignedPreKeyPublic.Length != Constants.X25519PublicKeySize)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.PeerPubKey("Invalid remote SignedPreKeyPublic key length."));

        foreach (OneTimePreKeyRecord opk in remoteBundle.OneTimePreKeys)
        {
            if (opk.PublicKey.Length != Constants.X25519PublicKeySize)
                return Result<Unit, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.PeerPubKey("Invalid remote OneTimePreKey public key length."));
        }

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

    private Result<SodiumSecureMemoryHandle?, EcliptixProtocolFailure> FindLocalOpkHandle(uint opkId)
    {
        foreach (OneTimePreKeyLocal opk in _oneTimePreKeysInternal)
        {
            if (opk.PreKeyId != opkId) continue;
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
        if (_disposed) return;

        if (disposing)
        {
            SecureCleanupLogic();
        }

        _disposed = true;
    }

    private void SecureCleanupLogic()
    {
        _ed25519SecretKeyHandle.Dispose();
        _identityX25519SecretKeyHandle.Dispose();
        _signedPreKeySecretKeyHandle.Dispose();
        _ephemeralSecretKeyHandle?.Dispose();
        foreach (OneTimePreKeyLocal opk in _oneTimePreKeysInternal) opk.Dispose();
        _oneTimePreKeysInternal.Clear();
        _oneTimePreKeysInternal = null!;
        _ephemeralSecretKeyHandle = null;
        if (_ephemeralX25519PublicKey != null) SodiumInterop.SecureWipe(_ephemeralX25519PublicKey).IgnoreResult();
        _ephemeralX25519PublicKey = null;

        _cachedProtoState = null;
        _lastOpkCount = -1;
    }

    ~EcliptixSystemIdentityKeys()
    {
        Dispose(false);
    }
}