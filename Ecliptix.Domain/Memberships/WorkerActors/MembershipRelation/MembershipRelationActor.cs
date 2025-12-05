using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents.Contact;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.QueryResults;
using Ecliptix.Protobuf.Contact;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Configuration;
using Serilog;
using DomainContactFailure = Ecliptix.Domain.Memberships.Failures.ContactFailure;
using DomainContactStatus = Ecliptix.Domain.Schema.Entities.ContactStatus;
using ProtoContactStatus = Ecliptix.Protobuf.Contact.ContactStatus;

namespace Ecliptix.Domain.Memberships.WorkerActors.MembershipRelation;

public sealed class MembershipRelationActor : ReceiveActor
{
    private readonly IActorRef _membershipRelationPersistor;

    public MembershipRelationActor(IActorRef membershipRelationPersistor)
    {
        _membershipRelationPersistor = membershipRelationPersistor;

        ReceiveAsync<RemoveContactEvent>(HandleRemoveFriend);
        ReceiveAsync<GetContactStatusEvent>(HandleGetContactStatus);
        ReceiveAsync<BlockContactEvent>(HandleBlockUser);
        ReceiveAsync<UnblockContactEvent>(HandleUnblockUser);
        ReceiveAsync<ListContactsEvent>(HandleListContacts);
        ReceiveAsync<MuteContactEvent>(HandleMuteContact);
        ReceiveAsync<UnmuteContactEvent>(HandleUnmuteContact);
    }

    public static Props Build(IActorRef membershipRelationPersistor)
    {
        return Props.Create(() => new MembershipRelationActor(membershipRelationPersistor));
    }

    private async Task HandleRemoveFriend(RemoveContactEvent evt)
    {
        IActorRef replyTo = Sender;

        try
        {
            Task<Result<ModifyContactResult, DomainContactFailure>> task =
                _membershipRelationPersistor.Ask<Result<ModifyContactResult, DomainContactFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<ModifyContactResult, DomainContactFailure> result = await task;

            Result<GenericResponse, DomainContactFailure> response = result.Match(
                ok: _ => Result<GenericResponse, DomainContactFailure>.Ok(new GenericResponse { Ok = true }),
                err: failure =>
                {
                    if (failure.IsUserFacing)
                    {
                        return Result<GenericResponse, DomainContactFailure>.Ok(
                            new GenericResponse { Ok = false, Message = failure.Message });
                    }

                    return Result<GenericResponse, DomainContactFailure>.Err(failure);
                }
            );

            replyTo.Tell(response);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[MEMBERSHIP-RELATION-ACTOR] Error handling RemoveFriend");
            replyTo.Tell(Result<GenericResponse, DomainContactFailure>.Err(
                DomainContactFailure.UnexpectedError("Failed to remove friend", ex)));
        }
    }

    private async Task HandleGetContactStatus(GetContactStatusEvent evt)
    {
        IActorRef replyTo = Sender;

        try
        {
            Task<Result<ContactStatusQueryRecord, DomainContactFailure>> task =
                _membershipRelationPersistor.Ask<Result<ContactStatusQueryRecord, DomainContactFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<ContactStatusQueryRecord, DomainContactFailure> result = await task;

            Result<GetContactStatusResponse, DomainContactFailure> response = result.Match(
                ok: record =>
                {
                    if (record.Status == null)
                    {
                        return Result<GetContactStatusResponse, DomainContactFailure>.Ok(
                            new GetContactStatusResponse
                            {
                                Status = ProtoContactStatus.None
                            });
                    }

                    ProtoContactStatus status = record.Status.Value switch
                    {
                        DomainContactStatus.Blocked => ProtoContactStatus.Blocked,
                        _ => ProtoContactStatus.None
                    };

                    GetContactStatusResponse statusResponse = new()
                    {
                        Status = status
                    };

                    if (record.Since.HasValue)
                    {
                        statusResponse.Since = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTimeOffset(
                            record.Since.Value);
                    }

                    return Result<GetContactStatusResponse, DomainContactFailure>.Ok(statusResponse);
                },
                err: failure => Result<GetContactStatusResponse, DomainContactFailure>.Err(failure)
            );

            replyTo.Tell(response);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[MEMBERSHIP-RELATION-ACTOR] Error handling GetContactStatus");
            replyTo.Tell(Result<GetContactStatusResponse, DomainContactFailure>.Err(
                DomainContactFailure.UnexpectedError("Failed to get friendship status", ex)));
        }
    }

    private async Task HandleBlockUser(BlockContactEvent evt)
    {
        IActorRef replyTo = Sender;

        try
        {
            Task<Result<ModifyContactResult, DomainContactFailure>> task =
                _membershipRelationPersistor.Ask<Result<ModifyContactResult, DomainContactFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<ModifyContactResult, DomainContactFailure> result = await task;

            Result<GenericResponse, DomainContactFailure> response = result.Match(
                ok: _ => Result<GenericResponse, DomainContactFailure>.Ok(new GenericResponse { Ok = true }),
                err: failure =>
                {
                    if (failure.IsUserFacing)
                    {
                        return Result<GenericResponse, DomainContactFailure>.Ok(
                            new GenericResponse { Ok = false, Message = failure.Message });
                    }

                    return Result<GenericResponse, DomainContactFailure>.Err(failure);
                }
            );

            replyTo.Tell(response);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[MEMBERSHIP-RELATION-ACTOR] Error handling BlockUser");
            replyTo.Tell(Result<GenericResponse, DomainContactFailure>.Err(
                DomainContactFailure.UnexpectedError("Failed to block user", ex)));
        }
    }

    private async Task HandleUnblockUser(UnblockContactEvent evt)
    {
        IActorRef replyTo = Sender;

        try
        {
            Task<Result<ModifyContactResult, DomainContactFailure>> task =
                _membershipRelationPersistor.Ask<Result<ModifyContactResult, DomainContactFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<ModifyContactResult, DomainContactFailure> result = await task;

            Result<GenericResponse, DomainContactFailure> response = result.Match(
                ok: _ => Result<GenericResponse, DomainContactFailure>.Ok(new GenericResponse { Ok = true }),
                err: failure =>
                {
                    if (failure.IsUserFacing)
                    {
                        return Result<GenericResponse, DomainContactFailure>.Ok(
                            new GenericResponse { Ok = false, Message = failure.Message });
                    }

                    return Result<GenericResponse, DomainContactFailure>.Err(failure);
                }
            );

            replyTo.Tell(response);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[MEMBERSHIP-RELATION-ACTOR] Error handling UnblockUser");
            replyTo.Tell(Result<GenericResponse, DomainContactFailure>.Err(
                DomainContactFailure.UnexpectedError("Failed to unblock user", ex)));
        }
    }

    private async Task HandleListContacts(ListContactsEvent evt)
    {
        IActorRef replyTo = Sender;

        try
        {
            Task<Result<ListContactsResponse, DomainContactFailure>> task =
                _membershipRelationPersistor.Ask<Result<ListContactsResponse, DomainContactFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<ListContactsResponse, DomainContactFailure> result = await task;

            replyTo.Tell(result);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[MEMBERSHIP-RELATION-ACTOR] Error handling ListContacts");
            replyTo.Tell(Result<ListContactsResponse, DomainContactFailure>.Err(
                DomainContactFailure.UnexpectedError("Failed to list contacts", ex)));
        }
    }

    private async Task HandleMuteContact(MuteContactEvent evt)
    {
        IActorRef replyTo = Sender;

        try
        {
            Task<Result<ModifyContactResult, DomainContactFailure>> task =
                _membershipRelationPersistor.Ask<Result<ModifyContactResult, DomainContactFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<ModifyContactResult, DomainContactFailure> result = await task;

            Result<GenericResponse, DomainContactFailure> response = result.Match(
                ok: _ => Result<GenericResponse, DomainContactFailure>.Ok(new GenericResponse { Ok = true }),
                err: failure =>
                {
                    if (failure.IsUserFacing)
                    {
                        return Result<GenericResponse, DomainContactFailure>.Ok(
                            new GenericResponse { Ok = false, Message = failure.Message });
                    }

                    return Result<GenericResponse, DomainContactFailure>.Err(failure);
                }
            );

            replyTo.Tell(response);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[MEMBERSHIP-RELATION-ACTOR] Error handling MuteContact");
            replyTo.Tell(Result<GenericResponse, DomainContactFailure>.Err(
                DomainContactFailure.UnexpectedError("Failed to mute contact", ex)));
        }
    }

    private async Task HandleUnmuteContact(UnmuteContactEvent evt)
    {
        IActorRef replyTo = Sender;

        try
        {
            Task<Result<ModifyContactResult, DomainContactFailure>> task =
                _membershipRelationPersistor.Ask<Result<ModifyContactResult, DomainContactFailure>>(
                    evt, TimeoutConfiguration.Actor.AskTimeout);

            Result<ModifyContactResult, DomainContactFailure> result = await task;

            Result<GenericResponse, DomainContactFailure> response = result.Match(
                ok: _ => Result<GenericResponse, DomainContactFailure>.Ok(new GenericResponse { Ok = true }),
                err: failure =>
                {
                    if (failure.IsUserFacing)
                    {
                        return Result<GenericResponse, DomainContactFailure>.Ok(
                            new GenericResponse { Ok = false, Message = failure.Message });
                    }

                    return Result<GenericResponse, DomainContactFailure>.Err(failure);
                }
            );

            replyTo.Tell(response);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[MEMBERSHIP-RELATION-ACTOR] Error handling UnmuteContact");
            replyTo.Tell(Result<GenericResponse, DomainContactFailure>.Err(
                DomainContactFailure.UnexpectedError("Failed to unmute contact", ex)));
        }
    }
}

