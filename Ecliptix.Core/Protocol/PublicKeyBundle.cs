using Ecliptix.Core.Protocol.Utilities;
using Google.Protobuf;

namespace Ecliptix.Core.Protocol;

/// <summary>
/// Represents the public part of a one-time prekey.
/// </summary>
public record OneTimePreKeyRecord(uint PreKeyId, byte[] PublicKey);

/// <summary>
/// Local C# representation of the public key bundle exchanged during X3DH setup.
/// Distinct from the Protobuf message used for wire transfer.
/// </summary>
public record LocalPublicKeyBundle
(
    byte[] IdentityEd25519,       // 32 bytes
    byte[] IdentityX25519,       // 32 bytes
    uint SignedPreKeyId,
    byte[] SignedPreKeyPublic,    // 32 bytes
    byte[] SignedPreKeySignature, // 64 bytes
    IReadOnlyList<OneTimePreKeyRecord> OneTimePreKeys,
    byte[]? EphemeralX25519        // 32 bytes, optional
)
{
    // Constants for validation consistency


    /// <summary>Converts this local record TO the Protobuf message used for EXCHANGE.</summary>
    public Protobuf.PubKeyExchange.PublicKeyBundle ToProtobufExchange()
    {
        var proto = new Protobuf.PubKeyExchange.PublicKeyBundle
        {
            IdentityPublicKey = ByteString.CopyFrom(IdentityEd25519), // Map local name to proto name
            IdentityX25519PublicKey = ByteString.CopyFrom(IdentityX25519),
            SignedPreKeyId = SignedPreKeyId,
            SignedPreKeyPublicKey = ByteString.CopyFrom(SignedPreKeyPublic),
            SignedPreKeySignature = ByteString.CopyFrom(SignedPreKeySignature)
        };

        if (EphemeralX25519 != null) {
            proto.EphemeralX25519PublicKey = ByteString.CopyFrom(EphemeralX25519);
        }

        foreach (var opkRecord in OneTimePreKeys) {
            // Note the nested type name from the PubKeyExchange.proto definition
            proto.OneTimePreKeys.Add(new Ecliptix.Protobuf.PubKeyExchange.PublicKeyBundle.Types.OneTimePreKey {
                PreKeyId = opkRecord.PreKeyId,
                PublicKey = ByteString.CopyFrom(opkRecord.PublicKey)
            });
        }
        return proto;
    }

    /// <summary>Creates this local record FROM the Protobuf message used for EXCHANGE.</summary>
    public static Result<LocalPublicKeyBundle, ShieldError> FromProtobufExchange(Ecliptix.Protobuf.PubKeyExchange.PublicKeyBundle proto)
    {
        if (proto == null) throw new ArgumentNullException(nameof(proto)); // Programming error

        try
        {
            var opkRecords = proto.OneTimePreKeys
                .Select(pOpk => new OneTimePreKeyRecord(pOpk.PreKeyId, pOpk.PublicKey.ToByteArray()))
                .ToList(); // Materialize the list for the record

            var bundle = new LocalPublicKeyBundle(
                IdentityEd25519: proto.IdentityPublicKey.ToByteArray(), // Map proto name to local name
                IdentityX25519: proto.IdentityX25519PublicKey.ToByteArray(),
                SignedPreKeyId: proto.SignedPreKeyId,
                SignedPreKeyPublic: proto.SignedPreKeyPublicKey.ToByteArray(),
                SignedPreKeySignature: proto.SignedPreKeySignature.ToByteArray(),
                OneTimePreKeys: opkRecords,
                EphemeralX25519: proto.EphemeralX25519PublicKey.IsEmpty
                    ? null
                    : proto.EphemeralX25519PublicKey.ToByteArray()
            );
            // Validation (lengths, etc.) happens in the record constructor
            return Result<LocalPublicKeyBundle, ShieldError>.Ok(bundle);
        }
        catch (ArgumentException ex) // Catch validation errors from record constructor
        {
            return Result<LocalPublicKeyBundle, ShieldError>.Err(
                ShieldError.Decode($"Failed to create LocalPublicKeyBundle from Protobuf: {ex.Message}", ex));
        }
        catch (Exception ex) // Catch other potential errors (e.g., ToByteArray)
        {
            return Result<LocalPublicKeyBundle, ShieldError>.Err(
                ShieldError.Decode($"Unexpected error creating LocalPublicKeyBundle from Protobuf: {ex.Message}", ex));
        }
    }
}
