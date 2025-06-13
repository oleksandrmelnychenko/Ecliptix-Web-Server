using Ecliptix.Protobuf.Membership;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record InitiateFlowAndReturnStateActorEvent(
    Guid AppDeviceId,
    Guid PhoneNumberId,
    VerificationPurpose Purpose,
    uint? ConnectId
);