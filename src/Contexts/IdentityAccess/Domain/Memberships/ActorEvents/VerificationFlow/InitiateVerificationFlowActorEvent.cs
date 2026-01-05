using System.Diagnostics;
using System.Threading.Channels;
using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;
using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.Protobuf.Membership;
using Ecliptix.SharedKernel;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.VerificationFlow;

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
