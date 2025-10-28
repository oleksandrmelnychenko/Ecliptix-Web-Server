using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.ProtocolState;

namespace Ecliptix.Core.Domain.Protocol.Handlers;

public sealed record EncryptionMaterialsResult(
    EcliptixSessionState NewState,
    EnvelopeMetadata Header,
    byte[] EncryptedPayload,
    bool ShouldPersist
);
