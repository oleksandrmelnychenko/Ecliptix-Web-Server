using Ecliptix.Protobuf.PubKeyExchange;

namespace Ecliptix.Core.Actors.Messages;

public record InitiateSession(uint SessionId, PubKeyExchangeType PubKeyExchangeType, PubKeyExchange PubKeyExchange);

public record SendMessage(uint SessionId, byte[] Buffer);

public record ReceiveMessage(uint SessionId, uint Index, byte[] Ciphertext, byte[]? DhPublicKey);

public record ShutdownSession(uint SessionId);