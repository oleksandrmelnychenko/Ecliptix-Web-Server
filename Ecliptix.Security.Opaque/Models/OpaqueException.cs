namespace Ecliptix.Security.Opaque.Models;

public class OpaqueException : Exception
{
    public OpaqueResult Result { get; }

    public OpaqueException(OpaqueResult result, string message) : base(message)
    {
        Result = result;
    }

    public OpaqueException(OpaqueResult result, string message, Exception innerException) : base(message, innerException)
    {
        Result = result;
    }
}

public class OpaqueAuthenticationException : OpaqueException
{
    public OpaqueAuthenticationException(string message) : base(OpaqueResult.AuthenticationError, message)
    {
    }
}

public class OpaqueValidationException : OpaqueException
{
    public OpaqueValidationException(string message) : base(OpaqueResult.ValidationError, message)
    {
    }
}