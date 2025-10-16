using System.Diagnostics.CodeAnalysis;

namespace Ecliptix.Utilities;

public readonly struct Result<T, TE> : IEquatable<Result<T, TE>>
{
    private readonly T? _value;
    private readonly TE? _error;

    private Result(T value, bool isOk)
    {
        _value = value;
        _error = default;
        IsOk = isOk;
    }

    private Result(TE error)
    {
        _value = default;
        _error = error;
        IsOk = false;
    }

    public static Result<T, TE> Ok(T value)
    {
        return new Result<T, TE>(value, true);
    }

    public static Result<T, TE> Err(TE error)
    {
        ArgumentNullException.ThrowIfNull(error, nameof(error));
        return new Result<T, TE>(error);
    }

    public static Result<T, TE> FromValue(T? value, TE errorWhenNull)
    {
        ArgumentNullException.ThrowIfNull(errorWhenNull, nameof(errorWhenNull));
        return value switch
        {
            not null => Ok(value),
            _ => Err(errorWhenNull)
        };
    }

    public static Result<T, TE> Validate(T value, Func<T, bool> predicate, TE errorWhenInvalid)
    {
        ArgumentNullException.ThrowIfNull(predicate, nameof(predicate));
        ArgumentNullException.ThrowIfNull(errorWhenInvalid, nameof(errorWhenInvalid));
        return predicate(value) ? Ok(value) : Err(errorWhenInvalid);
    }

    public static Result<T, TE> Try(Func<T> func, Func<Exception, TE> errorMapper)
    {
        ArgumentNullException.ThrowIfNull(func, nameof(func));
        ArgumentNullException.ThrowIfNull(errorMapper, nameof(errorMapper));
        try
        {
            return Ok(func());
        }
        catch (Exception ex) when (ex is not ThreadAbortException and not StackOverflowException)
        {
            TE error = errorMapper(ex);
            if (error == null)
                throw new InvalidOperationException("Error mapper returned null, violating TE : notnull");
            return Err(error);
        }
    }

    public static Result<Unit, TE> Try(Action action, Func<Exception, TE> errorMapper, Action? cleanup = null)
    {
        ArgumentNullException.ThrowIfNull(action, nameof(action));
        ArgumentNullException.ThrowIfNull(errorMapper, nameof(errorMapper));
        try
        {
            action();
            return Result<Unit, TE>.Ok(Unit.Value);
        }
        catch (Exception ex) when (ex is not ThreadAbortException and not StackOverflowException)
        {
            TE? error = errorMapper(ex);
            if (error == null)
                throw new InvalidOperationException("Error mapper returned null, violating TE : notnull");
            return Result<Unit, TE>.Err(error);
        }
        finally
        {
            cleanup?.Invoke();
        }
    }

    [MemberNotNullWhen(true, nameof(_value))]
    [MemberNotNullWhen(false, nameof(_error))]
    public bool IsOk { get; }

    [MemberNotNullWhen(false, nameof(_value))]
    [MemberNotNullWhen(true, nameof(_error))]
    public bool IsErr => !IsOk;

    public T Unwrap()
    {
        return IsOk ? _value! : throw new InvalidOperationException("Cannot unwrap an Err result");
    }

    public TE UnwrapErr()
    {
        return IsOk ? throw new InvalidOperationException("Cannot unwrap an Ok result") : _error!;
    }

    public T? UnwrapOr(T? defaultValue)
    {
        return IsOk ? _value : defaultValue;
    }

    public Result<TNext, TE> Map<TNext>(Func<T, TNext> mapFn)
    {
        return IsOk ? Result<TNext, TE>.Ok(mapFn(_value!)) : Result<TNext, TE>.Err(_error!);
    }

    public Result<T, TENext> MapErr<TENext>(Func<TE, TENext> mapFn) where TENext : notnull
    {
        return IsOk ? Result<T, TENext>.Ok(_value!) : Result<T, TENext>.Err(mapFn(_error!));
    }

    public Result<TNext, TE> Bind<TNext>(Func<T, Result<TNext, TE>> bindFn)
    {
        return IsOk ? bindFn(_value!) : Result<TNext, TE>.Err(_error!);
    }

    public TOut Match<TOut>(Func<T, TOut> ok, Func<TE, TOut> err)
    {
        return IsOk ? ok(_value!) : err(_error!);
    }

    public void Switch(Action<T> onOk, Action<TE> onErr)
    {
        if (IsOk) onOk(_value!);
        else onErr(_error!);
    }

    public override string ToString()
    {
        return IsOk ? "Ok" : "Err";
    }

    public bool Equals(Result<T, TE> other)
    {
        return IsOk == other.IsOk &&
               (IsOk
                   ? EqualityComparer<T?>.Default.Equals(_value, other._value)
                   : EqualityComparer<TE>.Default.Equals(_error, other._error));
    }

    public override bool Equals(object? obj)
    {
        return obj is Result<T, TE> other && Equals(other);
    }

    public override int GetHashCode()
    {
        unchecked
        {
            int hash = 17;
            hash = hash * 31 + IsOk.GetHashCode();
            hash = hash * 31 + (IsOk
                ? EqualityComparer<T?>.Default.GetHashCode(_value)
                : EqualityComparer<TE>.Default.GetHashCode(_error!));
            return hash;
        }
    }

    public static bool operator ==(Result<T, TE> left, Result<T, TE> right)
    {
        return left.Equals(right);
    }

    public static bool operator !=(Result<T, TE> left, Result<T, TE> right)
    {
        return !left.Equals(right);
    }
}