using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.SharedKernel;

namespace Ecliptix.IdentityAccess.Domain.Memberships.MobileNumberValidation;

public interface IMobileNumberValidator
{
    Result<MobileNumberValidationResult, VerificationFlowFailure> ValidateMobileNumber(
        string mobileNumber, string cultureName, string? defaultRegion = null);
}
