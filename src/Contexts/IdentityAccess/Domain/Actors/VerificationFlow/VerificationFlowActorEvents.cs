using System.Threading.Channels;
using Akka.Actor;
using Ecliptix.IdentityAccess.Domain.Memberships;
using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.Protobuf.Membership;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Actors;
using OtpVerificationPurpose = Ecliptix.IdentityAccess.Domain.Memberships.OtpVerificationPurpose;

namespace Ecliptix.IdentityAccess.Domain.Actors.VerificationFlow;

public sealed record ReplaceChannelWriterCommand(
    uint ConnectId,
    ChannelWriter<Result<OtpCountdownUpdate, VerificationFlowFailure>> NewWriter);

public record ProtocolCleanupRequiredEvent(uint ConnectId);

public sealed record CheckFlowValidityQuery;

public record VerifyMobileForSecretKeyRecoveryActorEvent(
    string MobileNumber,
    string? RegionCode,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record InitiateFlowAndReturnStateActorEvent(
    Guid AppDeviceId,
    Guid MobileNumberUniqueId,
    OtpVerificationPurpose Purpose,
    uint? ConnectId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record ExpirePasswordRecoveryFlowsEvent(Guid MembershipIdentifier, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;

public record VerifyFlowActorEvent(
    uint ConnectId,
    string OneTimePassword,
    string CultureName,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record QueryFlowStatusByConnectionIdActorEvent(
    uint ConnectionId,
    CancellationToken CancellationToken) : ICancellableActorEvent;

public record PasswordRecoveryFlowValidation(bool IsValid, Guid? FlowId);

public record FlowCompletedGracefullyActorEvent(IActorRef ActorRef);

public record VerificationFlowExpiredEvent(string CultureName);

public record ValidatePasswordRecoveryFlowEvent(Guid MembershipIdentifier, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;

public sealed record FlowValidityResponse(bool IsValid);

public record UpdateVerificationFlowStatusActorEvent(
    Guid FlowIdentifier,
    VerificationFlowStatus Status,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record InitiateVerificationFlowActorEvent(
    uint ConnectId,
    Guid MobileNumberIdentifier,
    Guid AppDeviceIdentifier,
    OtpVerificationPurpose Purpose,
    OtpVerificationRequest.Types.Type RequestType,
    ChannelWriter<Result<OtpCountdownUpdate, VerificationFlowFailure>> ChannelWriter,
    string CultureName,
    Option<string> IdempotencyKey,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public sealed class FlowTerminationAcknowledged
{
    public static readonly FlowTerminationAcknowledged Instance = new();
    private FlowTerminationAcknowledged()
    {
    }
}
