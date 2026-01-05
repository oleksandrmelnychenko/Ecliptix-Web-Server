using Grpc.Core;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing;

/// <summary>
/// Minimal ServerCallContext surrogate to reuse existing gRPC service logic when called via the event envelope pipeline.
/// Carries headers (metadata) and cancellation; connectId/idempotency are injected through UserState.
/// </summary>
public sealed class GrpcCallContext : ServerCallContext
{
    private readonly Metadata _requestHeaders;
    private readonly CancellationToken _cancellationToken;
    private readonly string _host;
    private readonly string _method;

    private readonly Metadata _responseTrailers = new();
    private Status _status = new Status(StatusCode.OK, string.Empty);
    private WriteOptions? _writeOptions;

    public GrpcCallContext(string method, string host, Metadata requestHeaders, CancellationToken cancellationToken)
    {
        _method = method;
        _host = host;
        _requestHeaders = requestHeaders;
        _cancellationToken = cancellationToken;
    }

    protected override string MethodCore => _method;
    protected override string HostCore => _host;
    protected override string PeerCore => string.Empty;
    protected override DateTime DeadlineCore => DateTime.MaxValue;
    protected override Metadata RequestHeadersCore => _requestHeaders;
    protected override CancellationToken CancellationTokenCore => _cancellationToken;
    protected override Metadata ResponseTrailersCore => _responseTrailers;
    protected override Status StatusCore { get => _status; set => _status = value; }
    protected override WriteOptions? WriteOptionsCore { get => _writeOptions; set => _writeOptions = value; }

    protected override AuthContext AuthContextCore => new AuthContext(string.Empty, new Dictionary<string, List<AuthProperty>>());
    protected override ContextPropagationToken CreatePropagationTokenCore(ContextPropagationOptions? options) =>
        throw new NotSupportedException("Context propagation not supported in synthetic context.");
    protected override Task WriteResponseHeadersAsyncCore(Metadata responseHeaders) => Task.CompletedTask;
}
