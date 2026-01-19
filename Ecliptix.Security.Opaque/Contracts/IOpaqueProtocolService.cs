using System;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Security.Opaque.Models;
using Ecliptix.SharedKernel;

namespace Ecliptix.Security.Opaque.Contracts;

public interface IOpaqueProtocolService
{
    (byte[] Response, Guid AccountId, int KeyVersion) ProcessOprfRequest(byte[] oprfRequest, Guid accountId);

    Result<(OpaqueSignInInitResponse Response, byte[] ServerMac), OpaqueFailure> InitiateSignIn(
        OpaqueSignInInitRequest request, MembershipOpaqueQueryRecord queryRecord);

    Result<(SodiumSecureMemoryHandle SessionKeyHandle, SodiumSecureMemoryHandle MasterKeyHandle, OpaqueSignInFinalizeResponse Response), OpaqueFailure>
        CompleteSignInWithMasterKey(OpaqueSignInFinalizeRequest request, byte[]? serverMac, int keyVersion);
}
