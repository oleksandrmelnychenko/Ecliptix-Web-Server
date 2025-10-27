using System.Diagnostics;
using System.Threading;
using System.Threading.Channels;
using Ecliptix.Domain.Memberships.ActorEvents.Common;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Utilities;

namespace Ecliptix.Domain.Memberships.ActorEvents.VerificationFlow;

public record InitiateVerificationFlowActorEvent(
    uint ConnectId,
    Guid MobileNumberIdentifier,
    Guid AppDeviceIdentifier,
    VerificationPurpose Purpose,
    InitiateVerificationRequest.Types.Type RequestType,
    ChannelWriter<Result<VerificationCountdownUpdate, VerificationFlowFailure>> ChannelWriter,
    string CultureName,
    Option<string> IdempotencyKey,
    ActivityContext ActivityContext = default,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
