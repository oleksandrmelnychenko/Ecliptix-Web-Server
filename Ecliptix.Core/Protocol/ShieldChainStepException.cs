using System;
using System.Runtime.Serialization; // Required for the serialization constructor

namespace Ecliptix.Core.Protocol; // Or the appropriate namespace for your project

/// <summary>
/// Represents errors that occur during ShieldChainStep operations,
/// such as key derivation failures, index errors, or DH rotation problems.
/// </summary>
[Serializable] // Recommended for custom exceptions, especially if they might be serialized.
public class ShieldChainStepException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ShieldChainStepException"/> class.
    /// </summary>
    public ShieldChainStepException()
        : base("An error occurred within the ShieldChainStep operation.") // Provide a default message
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ShieldChainStepException"/> class
    /// with a specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public ShieldChainStepException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ShieldChainStepException"/> class
    /// with a specified error message and a reference to the inner exception that is
    /// the cause of this exception.
    /// </summary>
    /// <param name="message">The error message that explains the reason for the exception.</param>
    /// <param name="innerException">The exception that is the cause of the current exception,
    /// or a null reference if no inner exception is specified.</param>
    public ShieldChainStepException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}