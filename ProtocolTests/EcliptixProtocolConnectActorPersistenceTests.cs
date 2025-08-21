using System.Text;
using Akka.Actor;
using Akka.Persistence;
using Akka.Persistence.TestKit;
using Akka.TestKit;
using Ecliptix.Core.Protocol;
using Ecliptix.Core.Domain.Protocol;
using Ecliptix.Core.Domain.Actors;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.ProtocolState;
using Ecliptix.Protobuf.Protocol;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace ProtocolTests;

public class EcliptixProtocolConnectActorPersistenceTests(ITestOutputHelper output)
    : PersistenceTestKit(nameof(EcliptixProtocolConnectActorPersistenceTests), output)
{
    private IReadOnlyList<T> ReadAllEvents<T>(string persistenceId) where T : class
    {
        TestProbe? replayProbe = CreateTestProbe("replay-probe");
        JournalActorRef.Tell(new ReplayMessages(0, long.MaxValue, long.MaxValue, persistenceId, replayProbe.Ref));
        List<T> events = [];

        while (true)
        {
            object? message = replayProbe.ExpectMsg<object>(TimeSpan.FromSeconds(5));
            switch (message)
            {
                case ReplayedMessage replayed:
                    if (replayed.Persistent.Payload is T payload)
                    {
                        events.Add(payload);
                    }

                    break;
                case RecoverySuccess:
                    return events;
                case ReplayMessagesFailure failure:
                    throw new Xunit.Sdk.XunitException(
                        $"Failed to replay messages for '{persistenceId}': {failure.Cause.Message}");
            }
        }
    }

    private (EcliptixProtocolSystem client, PubKeyExchange clientInitialMsg) CreateClientAndInitialMessage(
        uint sessionId)
    {
        EcliptixSystemIdentityKeys clientKeys = EcliptixSystemIdentityKeys.Create(1).Unwrap();
        EcliptixProtocolSystem clientSystem = new(clientKeys);
        PubKeyExchange clientInitialMsg = clientSystem
            .BeginDataCenterPubKeyExchange(sessionId, PubKeyExchangeType.DataCenterEphemeralConnect).Unwrap();
        return (clientSystem, clientInitialMsg);
    }

    [Fact]
    public void Handshake_Persists_InitialState()
    {
        uint sessionId = 101;
        string persistenceId = $"connect-{sessionId}";
        (_, PubKeyExchange clientInitialMsg) = CreateClientAndInitialMessage(sessionId);
        IActorRef? actor = Sys.ActorOf(EcliptixProtocolConnectActor.Build(sessionId), persistenceId);

        actor.Tell(new DeriveSharedSecretActorEvent(sessionId, clientInitialMsg), TestActor);
        ExpectMsg<Result<DeriveSharedSecretReply, EcliptixProtocolFailure>>(r => r.IsOk);

        IReadOnlyList<EcliptixSessionState> persisted = ReadAllEvents<EcliptixSessionState>(persistenceId);

        persisted.Should().HaveCount(1);
        EcliptixSessionState persistedState = persisted.First();
        persistedState.ConnectId.Should().Be(sessionId);
        persistedState.PeerHandshakeMessage.Should().BeEquivalentTo(clientInitialMsg);
    }

    [Fact]
    public void Restart_After_Handshake_Recovers_And_Continues_Session()
    {
        uint sessionId = 202;
        string persistenceId = $"connect-{sessionId}";
        (EcliptixProtocolSystem client, PubKeyExchange clientInitialMsg) = CreateClientAndInitialMessage(sessionId);
        IActorRef? actorRef = Sys.ActorOf(EcliptixProtocolConnectActor.Build(sessionId), persistenceId);

        actorRef.Tell(new DeriveSharedSecretActorEvent(sessionId, clientInitialMsg), TestActor);
        DeriveSharedSecretReply serverReply = ExpectMsg<Result<DeriveSharedSecretReply, EcliptixProtocolFailure>>().Unwrap();
        client.CompleteDataCenterPubKeyExchange(serverReply.PubKeyExchange).IsOk.Should().BeTrue();

        string firstMessage = "hello from before the crash";
        CipherPayload firstCipher = client.ProduceOutboundMessage(Encoding.UTF8.GetBytes(firstMessage)).Unwrap();

        Watch(actorRef);
        Sys.Stop(actorRef);
        ExpectTerminated(actorRef);

        IActorRef? recoveredActorRef = Sys.ActorOf(EcliptixProtocolConnectActor.Build(sessionId), persistenceId);

        recoveredActorRef.Tell(
            new DecryptCipherPayloadActorEvent(PubKeyExchangeType.DataCenterEphemeralConnect, firstCipher), TestActor);

        Result<byte[], EcliptixProtocolFailure> decryptResult = ExpectMsg<Result<byte[], EcliptixProtocolFailure>>();
        decryptResult.IsOk.Should().BeTrue("recovered actor should decrypt message successfully");
        Encoding.UTF8.GetString(decryptResult.Unwrap()).Should().Be(firstMessage);
    }
}