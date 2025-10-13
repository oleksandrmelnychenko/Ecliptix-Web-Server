using System.Threading.Channels;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Protobuf.Account;
using Ecliptix.Utilities;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record InitiateVerificationFlowActorEvent(
    uint ConnectId,
    Guid MobileNumberIdentifier,
    Guid AppDeviceIdentifier,
    VerificationPurpose Purpose,
    InitiateVerificationRequest.Types.Type RequestType,
    ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>> ChannelWriter,
    string CultureName
);