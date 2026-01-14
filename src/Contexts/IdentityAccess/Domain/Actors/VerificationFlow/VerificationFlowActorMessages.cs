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

public sealed record IsFlowValidQuery;

public record VerifyMobileForSecretKeyRecoveryCommand(
    string MobileNumber,
    string? RegionCode,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record InitiateFlowCommand(
    Guid AppDeviceId,
    Guid MobileNumberUniqueId,
    OtpVerificationPurpose Purpose,
    uint? ConnectId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record ExpirePasswordRecoveryFlowsCommand(Guid MembershipIdentifier, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;

public record VerifyFlowCommand(
    uint ConnectId,
    string OneTimePassword,
    string CultureName,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record GetFlowStatusByConnectionIdQuery(
    uint ConnectionId,
    CancellationToken CancellationToken) : ICancellableActorEvent;

public record PasswordRecoveryFlowValidationResponse(bool IsValid, Guid? FlowId);

public record FlowCompletedGracefullyEvent(IActorRef ActorRef);

public record VerificationFlowExpiredEvent(string CultureName);

public record ValidatePasswordRecoveryFlowCommand(Guid MembershipIdentifier, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;

public sealed record FlowValidityResponse(bool IsValid);

public record UpdateVerificationFlowStatusCommand(
    Guid FlowIdentifier,
    VerificationFlowStatus Status,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record InitiateVerificationFlowCommand(
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
