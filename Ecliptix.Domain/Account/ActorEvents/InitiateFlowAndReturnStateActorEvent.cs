using Ecliptix.Protobuf.Account;

namespace Ecliptix.Domain.Account.ActorEvents;

public record InitiateFlowAndReturnStateActorEvent(
    Guid AppDeviceId,
    Guid MobileNumberUniqueId,
    VerificationPurpose Purpose,
    uint? ConnectId
);