using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Utilities;

namespace Ecliptix.Domain.Memberships.PhoneNumberValidation;

public interface IPhoneNumberValidator
{
    Result<PhoneNumberValidationResult, VerificationFlowFailure> ValidatePhoneNumber(
        string phoneNumber, string peerCulture, string? defaultRegion = null);
}