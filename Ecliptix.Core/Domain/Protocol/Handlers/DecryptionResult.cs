using Ecliptix.Protobuf.ProtocolState;

namespace Ecliptix.Core.Domain.Protocol.Handlers;

public sealed record DecryptionResult(
    EcliptixSessionState NewState,
    byte[] Plaintext,
    bool ShouldPersist,
    bool RequiresSessionClear
);
