using Ecliptix.SharedKernel;
using Google.Protobuf;

namespace Ecliptix.Core.Domain.Protocol;

public record OneTimePreKeyRecord(uint PreKeyId, byte[] PublicKey)
{
    public static Result<OneTimePreKeyRecord, EcliptixProtocolFailure> Create(uint preKeyId, byte[] publicKey)
    {
        if (publicKey.Length != Constants.X25519KeySize)
        {
            return Result<OneTimePreKeyRecord, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Decode(
                    $"One-time prekey public key must be {Constants.X25519KeySize} bytes."));
        }

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

    public Ecliptix.Protobuf.Protocol.PublicKeyBundle ToProtobufExchange()
    {
        Protobuf.Protocol.PublicKeyBundle proto = new()
        {
            IdentityPublicKey = ByteString.CopyFrom(IdentityEd25519.AsSpan()),
            IdentityX25519PublicKey = ByteString.CopyFrom(IdentityX25519.AsSpan()),
            SignedPreKeyId = SignedPreKeyId,
            SignedPreKeyPublicKey = ByteString.CopyFrom(SignedPreKeyPublic.AsSpan()),
            SignedPreKeySignature = ByteString.CopyFrom(SignedPreKeySignature.AsSpan())
        };

        if (EphemeralX25519 != null)
        {
            proto.EphemeralX25519PublicKey = ByteString.CopyFrom(EphemeralX25519.AsSpan());
        }

        foreach (OneTimePreKeyRecord opkRecord in OneTimePreKeys)
        {
            proto.OneTimePreKeys.Add(new Ecliptix.Protobuf.Protocol.PublicKeyBundle.Types.OneTimePreKey
            {
                PreKeyId = opkRecord.PreKeyId,
                PublicKey = ByteString.CopyFrom(opkRecord.PublicKey.AsSpan())
            });
        }

        return proto;
    }

    public static Result<PublicKeyBundle, EcliptixProtocolFailure> FromProtobufExchange(
        Ecliptix.Protobuf.Protocol.PublicKeyBundle? proto)
    {
        if (proto == null)
        {
            return Result<PublicKeyBundle, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.InvalidInput("Input Protobuf bundle cannot be null."));
        }

        try
        {

            Result<(byte[] IdEd25519, byte[] IdX25519, byte[] SpkPublic, byte[] SpkSig), EcliptixProtocolFailure> requiredKeysResult =
                ExtractAndValidateRequiredKeys(proto);
            if (requiredKeysResult.IsErr)
            {
                return Result<PublicKeyBundle, EcliptixProtocolFailure>.Err(requiredKeysResult.UnwrapErr());
            }
            (byte[] IdEd25519, byte[] IdX25519, byte[] SpkPublic, byte[] SpkSig) requiredKeys = requiredKeysResult.Unwrap();

            Result<byte[]?, EcliptixProtocolFailure> ephemeralKeyResult =
                ExtractAndValidateOptionalEphemeralKey(proto.EphemeralX25519PublicKey);
            if (ephemeralKeyResult.IsErr)
            {
                return Result<PublicKeyBundle, EcliptixProtocolFailure>.Err(ephemeralKeyResult.UnwrapErr());
            }
            byte[]? ephemeralX25519 = ephemeralKeyResult.Unwrap();

            Result<List<OneTimePreKeyRecord>, EcliptixProtocolFailure> opkRecordsResult =
                ExtractAndValidateOneTimePreKeys(proto.OneTimePreKeys);
            if (opkRecordsResult.IsErr)
            {
                return Result<PublicKeyBundle, EcliptixProtocolFailure>.Err(opkRecordsResult.UnwrapErr());
            }
            List<OneTimePreKeyRecord> opkRecords = opkRecordsResult.Unwrap();

            InternalBundleData internalData = new()
            {
                IdentityEd25519 = requiredKeys.IdEd25519,
                IdentityX25519 = requiredKeys.IdX25519,
                SignedPreKeyId = proto.SignedPreKeyId,
                SignedPreKeyPublic = requiredKeys.SpkPublic,
                SignedPreKeySignature = requiredKeys.SpkSig,
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

    private static Result<(byte[] IdEd25519, byte[] IdX25519, byte[] SpkPublic, byte[] SpkSig), EcliptixProtocolFailure>
        ExtractAndValidateRequiredKeys(Ecliptix.Protobuf.Protocol.PublicKeyBundle proto)
    {
        Func<EcliptixProtocolFailure, Result<(byte[] IdEd25519, byte[] IdX25519, byte[] SpkPublic, byte[] SpkSig), EcliptixProtocolFailure>>
            errorResultType = Result<(byte[] IdEd25519, byte[] IdX25519, byte[] SpkPublic, byte[] SpkSig), EcliptixProtocolFailure>.Err;

        SecureByteStringInterop.SecureCopyWithCleanup(proto.IdentityPublicKey, out byte[] identityEd25519);
        SecureByteStringInterop.SecureCopyWithCleanup(proto.IdentityX25519PublicKey, out byte[] identityX25519);
        SecureByteStringInterop.SecureCopyWithCleanup(proto.SignedPreKeyPublicKey, out byte[] signedPreKeyPublic);
        SecureByteStringInterop.SecureCopyWithCleanup(proto.SignedPreKeySignature, out byte[] signedPreKeySignature);

        if (identityEd25519.Length != Constants.Ed25519KeySize)
        {
            return errorResultType(
                EcliptixProtocolFailure.Decode($"IdentityEd25519 key must be {Constants.Ed25519KeySize} bytes."));
        }

        if (identityX25519.Length != Constants.X25519KeySize)
        {
            return errorResultType(
                EcliptixProtocolFailure.Decode($"IdentityX25519 key must be {Constants.X25519KeySize} bytes."));
        }

        Result<Unit, EcliptixProtocolFailure> identityX25519ValidationResult = DhValidator.ValidateX25519PublicKey(identityX25519);
        if (identityX25519ValidationResult.IsErr)
        {
            return errorResultType(identityX25519ValidationResult.UnwrapErr());
        }

        if (signedPreKeyPublic.Length != Constants.X25519KeySize)
        {
            return errorResultType(
                EcliptixProtocolFailure.Decode($"SignedPreKeyPublic key must be {Constants.X25519KeySize} bytes."));
        }

        Result<Unit, EcliptixProtocolFailure> signedPreKeyValidationResult = DhValidator.ValidateX25519PublicKey(signedPreKeyPublic);
        if (signedPreKeyValidationResult.IsErr)
        {
            return errorResultType(signedPreKeyValidationResult.UnwrapErr());
        }

        if (signedPreKeySignature.Length != Constants.Ed25519SignatureSize)
        {
            return errorResultType(
                EcliptixProtocolFailure.Decode($"SignedPreKeySignature must be {Constants.Ed25519SignatureSize} bytes."));
        }

        Result<bool, Ecliptix.SharedKernel.Failures.Sodium.SodiumFailure> signatureVerificationResult =
            SodiumInterop.VerifyDetached(signedPreKeySignature, signedPreKeyPublic, identityEd25519);

        if (signatureVerificationResult.IsErr)
        {
            Ecliptix.SharedKernel.Failures.Sodium.SodiumFailure sodiumError = signatureVerificationResult.UnwrapErr();
            return errorResultType(
                EcliptixProtocolFailure.Decode($"SPK signature verification failed: {sodiumError.Message}"));
        }

        bool isSignatureValid = signatureVerificationResult.Unwrap();
        if (!isSignatureValid)
        {
            return errorResultType(
                EcliptixProtocolFailure.Decode("SPK signature is invalid - signed pre-key was not signed by the identity key"));
        }

        return Result<(byte[], byte[], byte[], byte[]), EcliptixProtocolFailure>.Ok(
            (identityEd25519, identityX25519, signedPreKeyPublic, signedPreKeySignature));
    }

    private static Result<byte[]?, EcliptixProtocolFailure> ExtractAndValidateOptionalEphemeralKey(
        ByteString ephemeralKeyProto)
    {
        if (ephemeralKeyProto.IsEmpty)
        {
            return Result<byte[]?, EcliptixProtocolFailure>.Ok(null);
        }

        SecureByteStringInterop.SecureCopyWithCleanup(ephemeralKeyProto, out byte[] ephemeralX25519);
        if (ephemeralX25519.Length != Constants.X25519KeySize)
        {
            return Result<byte[]?, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Decode($"EphemeralX25519 key must be {Constants.X25519KeySize} bytes if present."));
        }

        Result<Unit, EcliptixProtocolFailure> ephemeralValidationResult = DhValidator.ValidateX25519PublicKey(ephemeralX25519);
        if (ephemeralValidationResult.IsErr)
        {
            return Result<byte[]?, EcliptixProtocolFailure>.Err(ephemeralValidationResult.UnwrapErr());
        }

        return Result<byte[]?, EcliptixProtocolFailure>.Ok(ephemeralX25519);
    }

    private static Result<List<OneTimePreKeyRecord>, EcliptixProtocolFailure> ExtractAndValidateOneTimePreKeys(
        Google.Protobuf.Collections.RepeatedField<Ecliptix.Protobuf.Protocol.PublicKeyBundle.Types.OneTimePreKey> preKeysProto)
    {
        List<OneTimePreKeyRecord> opkRecords = new(preKeysProto.Count);
        foreach (Ecliptix.Protobuf.Protocol.PublicKeyBundle.Types.OneTimePreKey? pOpk in preKeysProto)
        {
            SecureByteStringInterop.SecureCopyWithCleanup(pOpk.PublicKey, out byte[] opkPublicKey);
            Result<OneTimePreKeyRecord, EcliptixProtocolFailure> opkResult = OneTimePreKeyRecord.Create(pOpk.PreKeyId, opkPublicKey);
            if (opkResult.IsErr)
            {

                return Result<List<OneTimePreKeyRecord>, EcliptixProtocolFailure>.Err(opkResult.UnwrapErr());
            }

            opkRecords.Add(opkResult.Unwrap());
        }

        return Result<List<OneTimePreKeyRecord>, EcliptixProtocolFailure>.Ok(opkRecords);
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
