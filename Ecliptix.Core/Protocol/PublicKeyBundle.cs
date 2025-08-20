using Ecliptix.Domain.Utilities;
using Google.Protobuf;

namespace Ecliptix.Core.Protocol;

public record OneTimePreKeyRecord(uint PreKeyId, byte[] PublicKey)
{
    public static Result<OneTimePreKeyRecord, EcliptixProtocolFailure> Create(uint preKeyId, byte[] publicKey)
    {
        if (publicKey.Length != Constants.X25519KeySize)
            return Result<OneTimePreKeyRecord, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Decode(
                    $"One-time prekey public key must be {Constants.X25519KeySize} bytes."));

        return Result<OneTimePreKeyRecord, EcliptixProtocolFailure>.Ok(new OneTimePreKeyRecord(preKeyId, publicKey));
    }
}

public record PublicKeyBundle(
    byte[] IdentityEd25519,
    byte[] IdentityX25519,
    uint SignedPreKeyId,
    byte[] SignedPreKeyPublic,
    byte[] SignedPreKeySignature,
    IReadOnlyList<OneTimePreKeyRecord> OneTimePreKeys,
    byte[]? EphemeralX25519
)
{
    private PublicKeyBundle(InternalBundleData data) : this(
        data.IdentityEd25519,
        data.IdentityX25519,
        data.SignedPreKeyId,
        data.SignedPreKeyPublic,
        data.SignedPreKeySignature,
        data.OneTimePreKeys,
        data.EphemeralX25519)
    {
    }

    public Protobuf.PubKeyExchange.PublicKeyBundle ToProtobufExchange()
    {
        Protobuf.PubKeyExchange.PublicKeyBundle proto = new()
        {
            IdentityPublicKey = ByteString.CopyFrom(IdentityEd25519.AsSpan()),
            IdentityX25519PublicKey = ByteString.CopyFrom(IdentityX25519.AsSpan()),
            SignedPreKeyId = SignedPreKeyId,
            SignedPreKeyPublicKey = ByteString.CopyFrom(SignedPreKeyPublic.AsSpan()),
            SignedPreKeySignature = ByteString.CopyFrom(SignedPreKeySignature.AsSpan())
        };

        if (EphemeralX25519 != null) proto.EphemeralX25519PublicKey = ByteString.CopyFrom(EphemeralX25519.AsSpan());

        foreach (OneTimePreKeyRecord opkRecord in OneTimePreKeys)
            proto.OneTimePreKeys.Add(new Protobuf.PubKeyExchange.PublicKeyBundle.Types.OneTimePreKey
            {
                PreKeyId = opkRecord.PreKeyId,
                PublicKey = ByteString.CopyFrom(opkRecord.PublicKey.AsSpan())
            });

        return proto;
    }

    public static Result<PublicKeyBundle, EcliptixProtocolFailure> FromProtobufExchange(
        Protobuf.PubKeyExchange.PublicKeyBundle? proto)
    {
        if (proto == null)
            return Result<PublicKeyBundle, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Input Protobuf bundle cannot be null."));

        try
        {
            SecureByteStringInterop.SecureCopyWithCleanup(proto.IdentityPublicKey, out byte[] identityEd25519);
            SecureByteStringInterop.SecureCopyWithCleanup(proto.IdentityX25519PublicKey, out byte[] identityX25519);
            SecureByteStringInterop.SecureCopyWithCleanup(proto.SignedPreKeyPublicKey, out byte[] signedPreKeyPublic);
            SecureByteStringInterop.SecureCopyWithCleanup(proto.SignedPreKeySignature, out byte[] signedPreKeySignature);

            if (identityEd25519.Length != Constants.Ed25519KeySize)
                return Result<PublicKeyBundle, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Decode($"IdentityEd25519 key must be {Constants.Ed25519KeySize} bytes."));
            
            if (identityX25519.Length != Constants.X25519KeySize)
                return Result<PublicKeyBundle, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Decode($"IdentityX25519 key must be {Constants.X25519KeySize} bytes."));

            Result<Unit, EcliptixProtocolFailure> identityX25519ValidationResult = DhValidator.ValidateX25519PublicKey(identityX25519);
            if (identityX25519ValidationResult.IsErr)
                return Result<PublicKeyBundle, EcliptixProtocolFailure>.Err(identityX25519ValidationResult.UnwrapErr());

            if (signedPreKeyPublic.Length != Constants.X25519KeySize)
                return Result<PublicKeyBundle, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Decode($"SignedPreKeyPublic key must be {Constants.X25519KeySize} bytes."));

            Result<Unit, EcliptixProtocolFailure> signedPreKeyValidationResult = DhValidator.ValidateX25519PublicKey(signedPreKeyPublic);
            if (signedPreKeyValidationResult.IsErr)
                return Result<PublicKeyBundle, EcliptixProtocolFailure>.Err(signedPreKeyValidationResult.UnwrapErr());

            if (signedPreKeySignature.Length != Constants.Ed25519SignatureSize)
                return Result<PublicKeyBundle, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Decode($"SignedPreKeySignature must be {Constants.Ed25519SignatureSize} bytes."));

            byte[]? ephemeralX25519 = null;
            if (!proto.EphemeralX25519PublicKey.IsEmpty)
            {
                SecureByteStringInterop.SecureCopyWithCleanup(proto.EphemeralX25519PublicKey, out ephemeralX25519);
                if (ephemeralX25519.Length != Constants.X25519KeySize)
                    return Result<PublicKeyBundle, EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.Decode($"EphemeralX25519 key must be {Constants.X25519KeySize} bytes if present."));

                Result<Unit, EcliptixProtocolFailure> ephemeralValidationResult = DhValidator.ValidateX25519PublicKey(ephemeralX25519);
                if (ephemeralValidationResult.IsErr)
                    return Result<PublicKeyBundle, EcliptixProtocolFailure>.Err(ephemeralValidationResult.UnwrapErr());
            }

            List<OneTimePreKeyRecord> opkRecords = new(proto.OneTimePreKeys.Count);
            foreach (Protobuf.PubKeyExchange.PublicKeyBundle.Types.OneTimePreKey? pOpk in proto.OneTimePreKeys)
            {
                SecureByteStringInterop.SecureCopyWithCleanup(pOpk.PublicKey, out byte[] opkPublicKey);
                Result<OneTimePreKeyRecord, EcliptixProtocolFailure> opkResult = OneTimePreKeyRecord.Create(pOpk.PreKeyId, opkPublicKey);
                if (opkResult.IsErr)
                    return Result<PublicKeyBundle, EcliptixProtocolFailure>.Err(opkResult.UnwrapErr());

                opkRecords.Add(opkResult.Unwrap());
            }

            InternalBundleData internalData = new()
            {
                IdentityEd25519 = identityEd25519,
                IdentityX25519 = identityX25519,
                SignedPreKeyId = proto.SignedPreKeyId,
                SignedPreKeyPublic = signedPreKeyPublic,
                SignedPreKeySignature = signedPreKeySignature,
                OneTimePreKeys = opkRecords,
                EphemeralX25519 = ephemeralX25519
            };
            return Result<PublicKeyBundle, EcliptixProtocolFailure>.Ok(new PublicKeyBundle(internalData));
        }
        catch (ArgumentException argEx)
        {
            return Result<PublicKeyBundle, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Decode(
                    $"Failed to create PublicKeyBundle from Protobuf due to invalid data: {argEx.Message}", argEx));
        }
        catch (Exception ex)
        {
            return Result<PublicKeyBundle, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Decode(
                    $"Unexpected error creating PublicKeyBundle from Protobuf: {ex.Message}", ex));
        }
    }

    private readonly struct InternalBundleData
    {
        public required byte[] IdentityEd25519 { get; init; }
        public required byte[] IdentityX25519 { get; init; }
        public required uint SignedPreKeyId { get; init; }
        public required byte[] SignedPreKeyPublic { get; init; }
        public required byte[] SignedPreKeySignature { get; init; }
        public required List<OneTimePreKeyRecord> OneTimePreKeys { get; init; }
        public required byte[]? EphemeralX25519 { get; init; }
    }
}