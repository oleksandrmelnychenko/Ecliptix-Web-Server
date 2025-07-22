using System.Globalization;
using Akka.Actor;
using Ecliptix.Core.Protocol.Actors;
using Ecliptix.Core.Services.Utilities;
using Ecliptix.Core.Services.Utilities.CipherPayloadHandler;
using Ecliptix.Domain.Memberships.WorkerActors;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Core.Services.Memberships;

public abstract class MembershipServicesBase(
    IEcliptixActorRegistry actorRegistry,
    ICipherPayloadHandler cipherPayloadHandler
    ) : Protobuf.Membership.MembershipServices.MembershipServicesBase
{
    protected readonly IActorRef MembershipActor = actorRegistry.Get<MembershipActor>();

    protected readonly ICipherPayloadHandler CipherPayloadHandler = cipherPayloadHandler;
    protected string CultureName { get; private set; } = CultureInfo.CurrentCulture.Name;
    
    
    protected async Task<CipherPayload> ExecuteWithDecryption<TRequest, TResponse>(
        CipherPayload encryptedRequest,
        ServerCallContext context,
        Func<TRequest, uint, CancellationToken, Task<CipherPayload>> handler)
        where TRequest : class, IMessage<TRequest>, new()
        where TResponse : class, IMessage<TResponse>, new()
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);


        Result<byte[], FailureBase> decryptionResult = await CipherPayloadHandler.DecryptRequest(encryptedRequest, connectId, context);

        if (decryptionResult.IsErr)
        {
            return await CipherPayloadHandler.RespondFailure<TResponse>(
                decryptionResult.UnwrapErr(), connectId, context);
        }

        byte[] decryptedBytes = decryptionResult.Unwrap();
        TRequest parsedRequest = Helpers.ParseFromBytes<TRequest>(decryptedBytes);

        return await handler(parsedRequest, connectId, context.CancellationToken);
    }
}