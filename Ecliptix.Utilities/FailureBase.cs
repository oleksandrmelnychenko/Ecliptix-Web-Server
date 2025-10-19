using Grpc.Core;

namespace Ecliptix.Utilities;

public interface IFailureBase
{
    object ToStructuredLog();
    Status ToGrpcStatus();
    GrpcErrorDescriptor ToGrpcDescriptor();
}

public abstract record FailureBase(string Message, Exception? InnerException = null) : IFailureBase
{
    protected DateTime Timestamp { get; } = DateTime.UtcNow;

    public abstract object ToStructuredLog();

    public virtual Status ToGrpcStatus()
    {
        GrpcErrorDescriptor descriptor = ToGrpcDescriptor();
        return descriptor.CreateStatus(Message);
    }

    public abstract GrpcErrorDescriptor ToGrpcDescriptor();
}
