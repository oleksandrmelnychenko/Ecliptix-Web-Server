using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Utilities;

namespace Ecliptix.Domain.Memberships.MobileNumberValidation;

public interface IMobileNumberValidator
{
    Result<MobileNumberValidationResult, VerificationFlowFailure> ValidateMobileNumber(
        string mobileNumber, string cultureName, string? defaultRegion = null);
}
