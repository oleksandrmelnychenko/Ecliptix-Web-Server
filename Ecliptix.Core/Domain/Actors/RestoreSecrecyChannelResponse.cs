namespace Ecliptix.Core.Domain.Actors;

/// <summary>
/// Internal actor message representing the result of a secrecy channel restore operation.
/// This is used for actor-to-actor communication, separate from the gRPC response type.
/// </summary>
public sealed class RestoreSecrecyChannelResponse
{
    public required Types.RestoreStatus Status { get; init; }
    public required uint ReceivingChainLength { get; init; }
    public required uint SendingChainLength { get; init; }

    public static class Types
    {
        public enum RestoreStatus
        {
            SessionNotFound = 0,
            SessionResumed = 1,
            SessionExpired = 2
        }
    }
}
