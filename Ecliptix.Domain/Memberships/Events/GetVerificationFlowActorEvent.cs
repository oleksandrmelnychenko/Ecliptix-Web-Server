using Ecliptix.Protobuf.Membership;

namespace Ecliptix.Domain.Memberships.Events;

public record GetVerificationFlowActorEvent(
    Guid DeviceId,
    Guid PhoneNumberIdentifier,
    VerificationPurpose Purpose);