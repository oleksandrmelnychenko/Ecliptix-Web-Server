using Grpc.Core;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing;

public sealed class GrpcCallContext(
    string method,
    string host,
    Metadata requestHeaders,
    CancellationToken cancellationToken)
    : ServerCallContext
{
    private static readonly DateTime DefaultDeadline = DateTime.UtcNow.AddYears(100);

    protected override string MethodCore => method;
    protected override string HostCore => host;
    protected override string PeerCore => string.Empty;
    protected override DateTime DeadlineCore => DefaultDeadline;
    protected override Metadata RequestHeadersCore => requestHeaders;
    protected override CancellationToken CancellationTokenCore => cancellationToken;
    protected override Metadata ResponseTrailersCore { get; } = [];
    protected override Status StatusCore { get; set; } = new(StatusCode.OK, string.Empty);
    protected override WriteOptions? WriteOptionsCore { get; set; }
    protected override AuthContext AuthContextCore => new(string.Empty, new Dictionary<string, List<AuthProperty>>());
    protected override ContextPropagationToken CreatePropagationTokenCore(ContextPropagationOptions? options) =>
        throw new NotSupportedException("Context propagation not supported in synthetic context.");
    protected override Task WriteResponseHeadersAsyncCore(Metadata responseHeaders) => Task.CompletedTask;
}
