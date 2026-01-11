using System;

namespace Ecliptix.Core.Infrastructure.Grpc.Security;

public interface IServerNonceStore
{
    void Store(uint connectId, byte[] nonce, TimeSpan ttl);
    bool TryTake(uint connectId, out byte[] nonce);
}
