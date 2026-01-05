using System.Threading.Channels;
using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.Protobuf.Membership;
using Ecliptix.SharedKernel;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.VerificationFlow;

public sealed record ReplaceChannelWriterCommand(
    uint ConnectId,
    ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>> NewWriter);
