using System;
using System.Collections.Generic;
using Ecliptix.Security.Opaque.Failures;
using Ecliptix.Security.Opaque.Models.AuthenticationMessages;
using Ecliptix.Security.Opaque.Models.RegistrationMessages;
using Ecliptix.SharedKernel;

namespace Ecliptix.Security.Opaque.Contracts;

public interface IOpaqueKeyRingService
{
    int ActiveKeyVersion { get; }

    Result<Unit, OpaqueRelayFailure> Initialize(IReadOnlyDictionary<int, string> keyRing, int activeKeyVersion);

    Result<RegistrationResponse, OpaqueRelayFailure> CreateRegistrationResponse(
        RegistrationRequest request,
        Guid accountId,
        int? keyVersion = null);

    Result<KE2, OpaqueRelayFailure> GenerateKe2(
        KE1 ke1,
        Guid accountId,
        byte[] registrationRecord,
        int keyVersion);

    Result<SodiumSecureMemoryHandle, OpaqueRelayFailure> FinishAuthenticationWithMasterKey(KE3 ke3, int keyVersion);

    Result<byte[], OpaqueRelayFailure> GetRelayPublicKey(int? keyVersion = null);
}
