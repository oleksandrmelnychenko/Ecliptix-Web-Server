using System;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Security.Opaque.Models;
using Ecliptix.Utilities;

namespace Ecliptix.Security.Opaque.Contracts;

public interface IOpaqueProtocolService
{
    (byte[] Response, Guid AccountId, int KeyVersion) ProcessOprfRequest(byte[] oprfRequest, Guid accountId);

    (byte[] Response, Guid AccountId, byte[] SessionKey, int KeyVersion) ProcessOprfRequestWithSessionKey(
        byte[] oprfRequest,
        Guid accountId);

    Result<(OpaqueSignInInitResponse Response, byte[] ServerMac), OpaqueFailure> InitiateSignIn(
        OpaqueSignInInitRequest request, MembershipOpaqueQueryRecord queryRecord);

    Result<(SodiumSecureMemoryHandle SessionKeyHandle, OpaqueSignInFinalizeResponse Response), OpaqueFailure> CompleteSignIn(
        OpaqueSignInFinalizeRequest request,
        byte[]? serverMac,
        int keyVersion);

    Result<(SodiumSecureMemoryHandle SessionKeyHandle, SodiumSecureMemoryHandle MasterKeyHandle, OpaqueSignInFinalizeResponse Response), OpaqueFailure>
        CompleteSignInWithMasterKey(OpaqueSignInFinalizeRequest request, byte[]? serverMac, int keyVersion);

    Result<byte[], OpaqueFailure> CompleteRegistrationWithSessionKey(byte[] peerRegistrationRecord);
}
