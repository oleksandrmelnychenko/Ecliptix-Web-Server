using System.Threading.Channels;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Utilities;

namespace Ecliptix.Domain.Memberships.ActorEvents.VerificationFlow;

public sealed record ReplaceChannelWriterCommand(
    uint ConnectId,
    ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>> NewWriter);
