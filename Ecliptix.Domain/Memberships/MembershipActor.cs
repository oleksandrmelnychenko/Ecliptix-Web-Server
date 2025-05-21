using Akka.Actor;

namespace Ecliptix.Domain.Memberships;

public record SignInMembershipActorCommand(string PhoneNumber, byte[] SecureKey);

public class MembershipActor : ReceiveActor
{
    private readonly IActorRef _persistor;

    public MembershipActor(IActorRef persistor)
    {
        _persistor = persistor;

        Become(Ready);
    }

    public static Props Build(IActorRef persistor) =>
        Props.Create(() => new MembershipActor(persistor));

    private void Ready()
    {
        Receive<CreateMembershipActorCommand>(HandleCreateMembershipActorCommand);
        Receive<SignInMembershipActorCommand>(HandleSignInMembershipActorCommand);
    }

    private void HandleSignInMembershipActorCommand(SignInMembershipActorCommand command)
    {
        _persistor.Forward(command);
    }

    private void HandleCreateMembershipActorCommand(CreateMembershipActorCommand command)
    {
        _persistor.Forward(command);
    }
}
