using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Utilities;

namespace Ecliptix.Domain.Memberships.PhoneNumberValidation;

public interface IPhoneNumberValidator
{
    Result<PhoneNumberValidationResult, VerificationFlowFailure> ValidatePhoneNumber(
        string phoneNumber, string cultureName, string? defaultRegion = null);
}