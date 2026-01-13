using Ecliptix.Protobuf.Membership;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents;

public record OprfCompleteRecoverySecureKeyEvent(
    Guid MembershipIdentifier,
    byte[] PeerRecoveryRecord,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

public record GenerateMembershipOprfRegistrationRequestEvent(
    Guid MembershipIdentifier,
    byte[]? OprfRequest,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

public record OprfInitRecoverySecureKeyEvent(
    Guid MembershipIdentifier,
    byte[] OprfRequest,
    string CultureName,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

public record CompleteRegistrationRecordActorEvent(
    Guid MembershipIdentifier,
    byte[] PeerRegistrationRecord,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

internal record CleanupExpiredPasswordRecovery;

public record UpdateAccountSecureKeyEvent(
    Guid MembershipIdentifier,
    byte[] SecureKey,
    byte[] MaskingKey,
    int OpaqueKeyVersion = 1,
    Guid? AccountId = null,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

internal record CleanupExpiredPendingSignIns;

public record SignInCompleteEvent(uint ConnectId, OpaqueSignInFinalizeRequest Request);
