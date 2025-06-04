using Ecliptix.Protobuf.Membership;

namespace Ecliptix.Domain.Memberships.Events;

public record CreateVerificationFlowActorEvent(
    Guid PhoneNumberIdentifier,
    Guid AppDeviceIdentifier,
    VerificationPurpose Purpose,
    DateTime ExpiresAt,
    uint ConnectId);