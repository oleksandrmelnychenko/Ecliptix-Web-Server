using Ecliptix.Security.Opaque.Models.AuthenticationMessages;
using Ecliptix.Security.Opaque.Models.RegistrationMessages;
using Ecliptix.Security.Opaque.Failures;
using Ecliptix.Utilities;

namespace Ecliptix.Security.Opaque.Services;

public interface INativeOpaqueProtocolService
{
    Result<Unit, OpaqueServerFailure> Initialize(string secretKeySeed);

    Result<(RegistrationResponse Response, byte[] ServerCredentials), OpaqueServerFailure> CreateRegistrationResponse(RegistrationRequest request);

    Result<KE2, OpaqueServerFailure> GenerateKe2(KE1 ke1, byte[] registrationRecord);

    Result<SessionKey, OpaqueServerFailure> FinishAuthentication(KE3 ke3);
}