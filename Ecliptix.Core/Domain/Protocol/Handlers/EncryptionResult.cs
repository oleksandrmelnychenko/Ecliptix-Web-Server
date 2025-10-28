using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.ProtocolState;

namespace Ecliptix.Core.Domain.Protocol.Handlers;

public sealed record EncryptionResult(
    EcliptixSessionState NewState,
    SecureEnvelope Envelope,
    bool ShouldPersist
);
