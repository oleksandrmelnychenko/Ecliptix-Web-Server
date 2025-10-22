using System.Threading.Channels;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Utilities;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public sealed record CheckSessionValidityQuery();

public sealed record SessionValidityResponse(bool IsValid, uint RemainingSeconds);

public sealed record ReplaceChannelWriterCommand(
    uint ConnectId,
    ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>> NewWriter);
