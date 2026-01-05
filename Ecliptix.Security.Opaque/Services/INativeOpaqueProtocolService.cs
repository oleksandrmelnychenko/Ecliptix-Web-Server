using System;
using Ecliptix.Security.Opaque.Failures;
using Ecliptix.Security.Opaque.Models.AuthenticationMessages;
using Ecliptix.Security.Opaque.Models.RegistrationMessages;
using Ecliptix.SharedKernel;

namespace Ecliptix.Security.Opaque.Services;

public interface INativeOpaqueProtocolService
{
    Result<Unit, OpaqueServerFailure> Initialize(string secretKeySeed);

    Result<RegistrationResponse, OpaqueServerFailure> CreateRegistrationResponse(RegistrationRequest request, Guid accountId);

    Result<KE2, OpaqueServerFailure> GenerateKe2(KE1 ke1, Guid accountId, byte[] registrationRecord);

    Result<SodiumSecureMemoryHandle, OpaqueServerFailure> FinishAuthentication(KE3 ke3);

    Result<(SodiumSecureMemoryHandle SessionKey, SodiumSecureMemoryHandle MasterKey), OpaqueServerFailure>
        FinishAuthenticationWithMasterKey(KE3 ke3);
}
