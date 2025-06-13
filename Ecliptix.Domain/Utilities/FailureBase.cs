using Grpc.Core;

namespace Ecliptix.Domain.Utilities;

public interface IFailureBase
{
    object ToStructuredLog();
    Status ToGrpcStatus();
}

public abstract record FailureBase(string Message, Exception? InnerException = null) : IFailureBase
{
    protected DateTime Timestamp { get; } = DateTime.UtcNow;

    public abstract object ToStructuredLog();

    public abstract Status ToGrpcStatus();
}