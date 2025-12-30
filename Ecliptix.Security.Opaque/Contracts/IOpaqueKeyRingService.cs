using System;
using System.Collections.Generic;
using Ecliptix.Security.Opaque.Failures;
using Ecliptix.Security.Opaque.Models.AuthenticationMessages;
using Ecliptix.Security.Opaque.Models.RegistrationMessages;
using Ecliptix.Utilities;

namespace Ecliptix.Security.Opaque.Contracts;

public interface IOpaqueKeyRingService
{
    int ActiveKeyVersion { get; }

    Result<Unit, OpaqueServerFailure> Initialize(IReadOnlyDictionary<int, string> keyRing, int activeKeyVersion);

    Result<RegistrationResponse, OpaqueServerFailure> CreateRegistrationResponse(
        RegistrationRequest request,
        Guid accountId,
        int? keyVersion = null);

    Result<KE2, OpaqueServerFailure> GenerateKe2(
        KE1 ke1,
        Guid accountId,
        byte[] registrationRecord,
        int keyVersion);

    Result<SodiumSecureMemoryHandle, OpaqueServerFailure> FinishAuthentication(
        KE3 ke3,
        int keyVersion);

    Result<(SodiumSecureMemoryHandle SessionKey, SodiumSecureMemoryHandle MasterKey), OpaqueServerFailure>
        FinishAuthenticationWithMasterKey(KE3 ke3, int keyVersion);

    Result<byte[], OpaqueServerFailure> GetServerPublicKey(int? keyVersion = null);
}
