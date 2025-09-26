using Ecliptix.Security.Opaque.Models.AuthenticationMessages;
using Ecliptix.Security.Opaque.Models.RegistrationMessages;
using Ecliptix.Security.Opaque.Failures;
using Ecliptix.Domain.Utilities;

namespace Ecliptix.Security.Opaque.Services;

public interface INativeOpaqueProtocolService
{
    Task<Result<Unit, OpaqueServerFailure>> InitializeAsync(string? secretKeySeed = null);

    Task<Result<(RegistrationResponse Response, byte[] ServerCredentials), OpaqueServerFailure>> CreateRegistrationResponseAsync(RegistrationRequest request);

    Task<Result<KE2, OpaqueServerFailure>> GenerateKE2Async(KE1 ke1, byte[] registrationRecord);

    Task<Result<SessionKey, OpaqueServerFailure>> FinishAuthenticationAsync(KE3 ke3);
}