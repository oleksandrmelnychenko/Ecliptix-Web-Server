using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;

namespace Ecliptix.Core.Actors.Messages;

public record BeginAppDeviceEphemeralConnectCommand(PubKeyExchange PubKeyExchange, uint UniqueConnectId = 0);
public record BeginBeginAppDeviceEphemeralConnectReply(Result<PubKeyExchange,ShieldFailure> PubKeyExchange);
public record BeginExchangeFailure(string ErrorMessage);

public record ProcessExchangeResponseCommand(PubKeyExchange PeerInitialMessage, uint SessionId = 0);
public record ProcessExchangeResponse(uint SessionId, PubKeyExchange ResponseMessage);
public record ProcessExchangeResponseFailure(string ErrorMessage);

public record CompleteExchangeCommand(uint SessionId, PubKeyExchangeType ExchangeType, PubKeyExchange PeerMessage);
public record CompleteExchangeResponse(uint SessionId);
public record CompleteExchangeFailure(string ErrorMessage);

public record SendOutboundMessageCommand(uint SessionId, PubKeyExchangeType ExchangeType, byte[] PlainPayload);
public record SendOutboundMessageResponse(CipherPayload CipherPayload);
public record SendOutboundMessageFailure(string ErrorMessage);

public record ProcessInboundMessageCommand(uint SessionId, PubKeyExchangeType ExchangeType, CipherPayload CipherPayload);
public record ProcessInboundMessageResponse(byte[] Plaintext);
public record ProcessInboundMessageFailure(string ErrorMessage);