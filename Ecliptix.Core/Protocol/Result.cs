using System.Diagnostics.CodeAnalysis;

namespace Ecliptix.Core.Protocol;

public readonly struct Result<T, TE> : IEquatable<Result<T, TE>> // Changed from ref struct, added IEquatable
    where TE : notnull // Common constraint: Error type should not be null
{
    private readonly T _value;
    private readonly TE _error;
    private readonly bool _isOk;

    private Result(T value)
    {
        ArgumentNullException.ThrowIfNull(value, nameof(value)); // Optional: prevent Ok(null) if desired, depends on semantics for T
        _value = value;
        _error = default!; // Allowed because _isOk is true, won't be accessed
        _isOk = true;
    }

    private Result(TE error)
    {
        // No null check needed due to 'where E : notnull' constraint
        _value = default!; // Allowed because _isOk is false, won't be accessed
        _error = error;
        _isOk = false;
    }

    /// <summary>
    /// Creates an Ok result with the specified value.
    /// </summary>
    public static Result<T, TE> Ok(T value) => new(value);

    /// <summary>
    /// Creates an Err result with the specified error.
    /// </summary>
    public static Result<T, TE> Err(TE error) => new(error);

    /// <summary>
    /// Returns true if the result is Ok.
    /// </summary>
    [MemberNotNullWhen(true, nameof(_value))] // Helps nullable analysis
    [MemberNotNullWhen(false, nameof(_error))] // Helps nullable analysis
    public bool IsOk => _isOk;

    /// <summary>
    /// Returns true if the result is Err.
    /// </summary>
    [MemberNotNullWhen(false, nameof(_value))] // Helps nullable analysis
    [MemberNotNullWhen(true, nameof(_error))] // Helps nullable analysis
    public bool IsErr => !_isOk;

    /// <summary>
    /// Gets the Ok value.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown if the result is Err.</exception>
    public T Unwrap()
    {
        if (!_isOk) throw new InvalidOperationException($"Called Unwrap on an Err result: {_error}"); // Improved message
        return _value;
    }

    /// <summary>
    /// Gets the Err value.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown if the result is Ok.</exception>
    public TE UnwrapErr()
    {
        if (_isOk) throw new InvalidOperationException($"Called UnwrapErr on an Ok result: {_value}"); // Improved message
        return _error;
    }

    /// <summary>
    /// Gets the Ok value, or a default value if the result is Err.
    /// </summary>
    public T UnwrapOr(T defaultValue)
    {
        return _isOk ? _value : defaultValue;
    }

    /// <summary>
    /// Gets the Ok value, or computes a fallback value from the error if the result is Err.
    /// </summary>
    public T UnwrapOrElse(Func<TE, T> fallbackFn)
    {
        ArgumentNullException.ThrowIfNull(fallbackFn);
        return _isOk ? _value : fallbackFn(_error);
    }

    /// <summary>
    /// Transforms the result's Ok value using the provided function.
    /// If the result is Err, the error is propagated.
    /// </summary>
    public Result<TNext, TE> Map<TNext>(Func<T, TNext> mapFn)
    {
        ArgumentNullException.ThrowIfNull(mapFn);
        return _isOk ? Result<TNext, TE>.Ok(mapFn(_value)) : Result<TNext, TE>.Err(_error);
    }

    /// <summary>
    /// Transforms the result's Err value using the provided function.
    /// If the result is Ok, the value is propagated.
    /// </summary>
    public Result<T, ENext> MapErr<ENext>(Func<TE, ENext> mapFn)
        where ENext: notnull // Keep the notnull constraint for the new error type
    {
        ArgumentNullException.ThrowIfNull(mapFn);
        return _isOk ? Result<T, ENext>.Ok(_value) : Result<T, ENext>.Err(mapFn(_error));
    }

    /// <summary>
    /// Chains a computation that returns a Result.
    /// If the current result is Ok, applies the function to the value.
    /// If the current result is Err, propagates the error.
    /// </summary>
    public Result<TNext, TE> AndThen<TNext>(Func<T, Result<TNext, TE>> bindFn)
    {
        ArgumentNullException.ThrowIfNull(bindFn);
        return _isOk ? bindFn(_value) : Result<TNext, TE>.Err(_error);
    }

    /// <summary>
    /// Processes the result using one of the provided functions, depending on whether it's Ok or Err.
    /// </summary>
    public TOut Match<TOut>(Func<T, TOut> ok, Func<TE, TOut> err)
    {
        ArgumentNullException.ThrowIfNull(ok);
        ArgumentNullException.ThrowIfNull(err);
        return _isOk ? ok(_value) : err(_error);
    }

    /// <summary>
    /// Returns a string representation of the result.
    /// </summary>
    public override string ToString()
    {
        return _isOk ? $"Ok({_value})" : $"Err({_error})";
    }

    // --- IEquatable Implementation ---

    public bool Equals(Result<T, TE> other)
    {
        if (_isOk != other._isOk)
        {
            return false;
        }
        return _isOk
            ? EqualityComparer<T>.Default.Equals(_value, other._value)
            : EqualityComparer<TE>.Default.Equals(_error, other._error);
        // Note: EqualityComparer<E> handles the 'notnull' constraint correctly
    }

    public override bool Equals(object? obj)
    {
        return obj is Result<T, TE> other && Equals(other);
    }

    public override int GetHashCode()
    {
        // Simple hash combining strategy
        int hash = _isOk.GetHashCode(); // Start with bool hash
        hash = (hash * 397) ^ (_isOk
            ? EqualityComparer<T>.Default.GetHashCode(_value!) // Use _value if Ok
            : EqualityComparer<TE>.Default.GetHashCode(_error)); // Use _error if Err
        return hash;
    }

    public static bool operator ==(Result<T, TE> left, Result<T, TE> right)
    {
        return left.Equals(right);
    }

    public static bool operator !=(Result<T, TE> left, Result<T, TE> right)
    {
        return !left.Equals(right);
    }

    // --- Optional: Implicit Conversions ---
    // Use with caution - can sometimes reduce clarity

    // public static implicit operator Result<T, E>(T value) => Ok(value);
    // public static implicit operator Result<T, E>(E error) => Err(error);
}