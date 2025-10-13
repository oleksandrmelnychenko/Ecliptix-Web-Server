using AccountProto = Ecliptix.Protobuf.Account.Account;

namespace Ecliptix.Domain.Account.ActorEvents;

public record CreateAccountActorEvent(
    uint ConnectId,
    Guid VerificationFlowIdentifier,
    Guid OtpIdentifier,
    AccountProto.Types.CreationStatus CreationStatus
);