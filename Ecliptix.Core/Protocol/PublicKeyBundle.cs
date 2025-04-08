using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.PubKeyExchange;
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
    public PublicKeyBundle ToProtobufExchange()
    {
        PublicKeyBundle proto = new()
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

        foreach (OneTimePreKeyRecord opkRecord in OneTimePreKeys) {
            proto.OneTimePreKeys.Add(new PublicKeyBundle.Types.OneTimePreKey {
                PreKeyId = opkRecord.PreKeyId,
                PublicKey = ByteString.CopyFrom(opkRecord.PublicKey)
            });
        }
        return proto;
    }

    public static Result<LocalPublicKeyBundle, ShieldError> FromProtobufExchange(PublicKeyBundle proto)
    {
        if (proto == null) throw new ArgumentNullException(nameof(proto)); 

        try
        {
            List<OneTimePreKeyRecord> opkRecords = proto.OneTimePreKeys
                .Select(pOpk => new OneTimePreKeyRecord(pOpk.PreKeyId, pOpk.PublicKey.ToByteArray()))
                .ToList();

            LocalPublicKeyBundle bundle = new(
                IdentityEd25519: proto.IdentityPublicKey.ToByteArray(), 
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
