using Ecliptix.Protobuf.Transport.Common;
using Google.Protobuf;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing;

internal sealed record DispatchContext
{
    public required EventEnvelope Envelope { get; init; }
    public required EventMetadata Metadata { get; init; }
    public EventRoute? Route { get; init; }
    public IMessage? Message { get; init; }
    public IMessage? Response { get; init; }

    public DispatchContext WithRoute(EventRoute route) => this with { Route = route };
    public DispatchContext WithMessage(IMessage message) => this with { Message = message };
    public DispatchContext WithResponse(IMessage response) => this with { Response = response };
}
