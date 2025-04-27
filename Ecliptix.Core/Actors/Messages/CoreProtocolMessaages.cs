using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.PubKeyExchange;

namespace Ecliptix.Core.Actors.Messages;

public record BeginAppDeviceEphemeralConnectCommand(PubKeyExchange PubKeyExchange, uint UniqueConnectId = 0);
public record BeginBeginAppDeviceEphemeralConnectReply(Result<PubKeyExchange,ShieldFailure> PubKeyExchange);
