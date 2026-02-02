using System;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Security.Opaque.Models;
using Ecliptix.SharedKernel;

namespace Ecliptix.Security.Opaque.Contracts;

public interface IOpaqueProtocolService
{
    (byte[] Response, int KeyVersion) ProcessOprfRequest(byte[] oprfRequest, Guid accountId);

    Result<(OpaqueSignInInitResponse Response, byte[] RelayMac), OpaqueFailure> InitiateSignIn(
        OpaqueSignInInitRequest request, MembershipOpaqueQueryRecord queryRecord);

    Result<(SodiumSecureMemoryHandle MasterKeyHandle, OpaqueSignInFinalizeResponse Response), OpaqueFailure>
        CompleteSignInWithMasterKey(OpaqueSignInFinalizeRequest request, byte[]? relayMac, int keyVersion);
}
