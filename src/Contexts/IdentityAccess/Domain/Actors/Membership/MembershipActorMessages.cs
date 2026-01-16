using Ecliptix.Protobuf.Membership;
using Ecliptix.SharedKernel.Actors;

namespace Ecliptix.IdentityAccess.Domain.Actors.Membership;

public record CompleteOprfSecureKeyRecoveryCommand(
    Guid MembershipIdentifier,
    byte[] PeerRecoveryRecord,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

public record GenerateOprfRegistrationCommand(
    Guid MembershipIdentifier,
    byte[]? OprfRequest,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

public record InitiateOprfSecureKeyRecoveryCommand(
    Guid MembershipIdentifier,
    byte[] OprfRequest,
    string CultureName,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

public record CompleteRegistrationCommand(
    Guid MembershipIdentifier,
    byte[] PeerRegistrationRecord,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

internal record CleanupExpiredPasswordRecovery;

public record UpdateAccountSecureKeyCommand(
    Guid MembershipIdentifier,
    byte[] SecureKey,
    byte[] MaskingKey,
    int OpaqueKeyVersion = 1,
    Guid? AccountId = null,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

public record EnsureAccountMaskingKeyCommand(
    Guid AccountId,
    byte[] MaskingKey,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

internal record CleanupExpiredPendingSignIns;

public record SignInCompleteEvent(uint ConnectId, OpaqueSignInFinalizeRequest Request);
