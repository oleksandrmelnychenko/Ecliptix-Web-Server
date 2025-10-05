namespace Ecliptix.Core.Domain.Protocol;

[Serializable]
public class ProtocolChainStepException : Exception
{
    public ProtocolChainStepException()
        : base("An error occurred within the ShieldChainStep operation.")
    {
    }

    public ProtocolChainStepException(string message)
        : base(message)
    {
    }

    public ProtocolChainStepException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}