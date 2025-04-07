using System.Diagnostics.CodeAnalysis;

namespace Ecliptix.Core.Protocol.Utilities;

public readonly struct Result<T, TE> : IEquatable<Result<T, TE>> where TE : notnull
{
    private readonly T _value;
    private readonly TE _error;

    private Result(T value)
    {
        ArgumentNullException.ThrowIfNull(value, nameof(value));
        _value = value;
        _error = default!;
        IsOk = true;
    }

    private Result(TE error)
    {
        _value = default!;
        _error = error;
        IsOk = false;
    }

    public static Result<T, TE> Ok(T value) => new(value);
    public static Result<T, TE> Err(TE error) => new(error);

    [MemberNotNullWhen(true, nameof(_value))]
    [MemberNotNullWhen(false, nameof(_error))]
    public bool IsOk { get; }

    [MemberNotNullWhen(false, nameof(_value))]
    [MemberNotNullWhen(true, nameof(_error))]
    public bool IsErr => !IsOk;

    public T Unwrap() =>
        IsOk ? _value : throw new InvalidOperationException($"Called Unwrap on an Err result: {_error}");

    public TE UnwrapErr() =>
        IsOk ? throw new InvalidOperationException($"Called UnwrapErr on an Ok result: {_value}") : _error;

    public T UnwrapOr(T defaultValue) => IsOk ? _value : defaultValue;
    public T UnwrapOrElse(Func<TE, T> fallbackFn) => IsOk ? _value : fallbackFn(_error);

    public Result<TNext, TE> Map<TNext>(Func<T, TNext> mapFn) =>
        IsOk ? Result<TNext, TE>.Ok(mapFn(_value)) : Result<TNext, TE>.Err(_error);

    public Result<T, TENext> MapErr<TENext>(Func<TE, TENext> mapFn) where TENext : notnull =>
        IsOk ? Result<T, TENext>.Ok(_value) : Result<T, TENext>.Err(mapFn(_error));

    public Result<TNext, TE> AndThen<TNext>(Func<T, Result<TNext, TE>> bindFn) =>
        IsOk ? bindFn(_value) : Result<TNext, TE>.Err(_error);

    public TOut Match<TOut>(Func<T, TOut> ok, Func<TE, TOut> err) => IsOk ? ok(_value) : err(_error);
    public override string ToString() => IsOk ? $"Ok({_value})" : $"Err({_error})";

    public bool Equals(Result<T, TE> other) => IsOk == other.IsOk &&
                                               (IsOk
                                                   ? EqualityComparer<T>.Default.Equals(_value, other._value)
                                                   : EqualityComparer<TE>.Default.Equals(_error, other._error));

    public override bool Equals(object? obj) => obj is Result<T, TE> other && Equals(other);

    public override int GetHashCode() => (IsOk.GetHashCode() * 397) ^ (IsOk
        ? EqualityComparer<T>.Default.GetHashCode(_value!)
        : EqualityComparer<TE>.Default.GetHashCode(_error));

    public static bool operator ==(Result<T, TE> left, Result<T, TE> right) => left.Equals(right);
    public static bool operator !=(Result<T, TE> left, Result<T, TE> right) => !left.Equals(right);
}