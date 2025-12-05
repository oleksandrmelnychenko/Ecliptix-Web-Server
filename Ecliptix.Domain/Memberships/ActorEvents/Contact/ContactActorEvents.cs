using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.Contact;

public record RemoveContactEvent(
    uint ConnectId,
    Guid MembershipId,
    Guid TargetMembershipId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record ListContactsEvent(
    uint ConnectId,
    Guid MembershipId,
    int Limit,
    string? Cursor,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record GetContactStatusEvent(
    uint ConnectId,
    Guid MembershipId,
    Guid OtherMembershipId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record BlockContactEvent(
    uint ConnectId,
    Guid ByMembershipId,
    Guid TargetMembershipId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record UnblockContactEvent(
    uint ConnectId,
    Guid ByMembershipId,
    Guid TargetMembershipId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record MuteContactEvent(
    uint ConnectId,
    Guid ByMembershipId,
    Guid TargetMembershipId,
    DateTimeOffset MutedUntil,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record UnmuteContactEvent(
    uint ConnectId,
    Guid ByMembershipId,
    Guid TargetMembershipId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
