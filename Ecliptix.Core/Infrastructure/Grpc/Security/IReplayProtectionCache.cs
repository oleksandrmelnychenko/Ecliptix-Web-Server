using System;

namespace Ecliptix.Core.Infrastructure.Grpc.Security;

public interface IReplayProtectionCache
{
    bool TryBegin(string scope, string key, TimeSpan ttl);
    void Release(string scope, string key);
}
