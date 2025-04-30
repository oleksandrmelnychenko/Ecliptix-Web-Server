using System.Diagnostics.CodeAnalysis;
using Ecliptix.Core.Protocol.Utilities;

namespace Ecliptix.Domain.Utilities;

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

    public static Result<T, TE> Ok(T value) => new(value, true);

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
            var error = errorMapper(ex);
            if (error == null)
                throw new InvalidOperationException("Error mapper returned null, violating TE : notnull");
            return Err(error);
        }
    }

    public static Result<T, TE> Try(Func<T> func, Func<Exception, bool> exceptionFilter,
        Func<Exception, TE> errorMapper)
    {
        ArgumentNullException.ThrowIfNull(func, nameof(func));
        ArgumentNullException.ThrowIfNull(exceptionFilter, nameof(exceptionFilter));
        ArgumentNullException.ThrowIfNull(errorMapper, nameof(errorMapper));
        try
        {
            return Ok(func());
        }
        catch (Exception ex) when (ex is not ThreadAbortException and not StackOverflowException && exceptionFilter(ex))
        {
            var error = errorMapper(ex);
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

    public static async ValueTask<Result<Unit, TError>> TryAsync<TError>(
        Func<ValueTask> action,
        Func<Exception, TError> errorMapper,
        Action? cleanup = null)
    {
        ArgumentNullException.ThrowIfNull(action, nameof(action));
        ArgumentNullException.ThrowIfNull(errorMapper, nameof(errorMapper));

        try
        {
            await action().ConfigureAwait(false);
            return Result<Unit, TError>.Ok(Unit.Value);
        }
        catch (Exception ex) when (ex is not ThreadAbortException and not StackOverflowException)
        {
            TError? error = errorMapper(ex);
            if (error == null)
                throw new InvalidOperationException("Error mapper returned null, violating TError : notnull");
            return Result<Unit, TError>.Err(error);
        }
        finally
        {
            cleanup?.Invoke();
        }
    }

    public static async ValueTask<Result<T, TError>> TryAsync<T, TError>(
        Func<ValueTask<T>> action,
        Func<ShieldFailure, TError> errorMapper,
        Action? cleanup = null)
    {
        ArgumentNullException.ThrowIfNull(action, nameof(action));
        ArgumentNullException.ThrowIfNull(errorMapper, nameof(errorMapper));

        try
        {
            T result = await action().ConfigureAwait(false);
            return Result<T, TError>.Ok(result);
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

    public T Unwrap() =>
        IsOk ? _value! : throw new InvalidOperationException("Cannot unwrap an Err result");

    public TE UnwrapErr() =>
        IsOk ? throw new InvalidOperationException("Cannot unwrap an Ok result") : _error!;

    public T? UnwrapOr(T? defaultValue) => IsOk ? _value : defaultValue;

    public T UnwrapOrElse(Func<TE, T> fallbackFn) => IsOk ? _value! : fallbackFn(_error!);

    public Result<TNext, TE> Map<TNext>(Func<T, TNext> mapFn) =>
        IsOk ? Result<TNext, TE>.Ok(mapFn(_value!)) : Result<TNext, TE>.Err(_error!);

    public Result<T, TENext> MapErr<TENext>(Func<TE, TENext> mapFn) where TENext : notnull =>
        IsOk ? Result<T, TENext>.Ok(_value!) : Result<T, TENext>.Err(mapFn(_error!));

    public Result<TNext, TE> Bind<TNext>(Func<T, Result<TNext, TE>> bindFn) =>
        IsOk ? bindFn(_value!) : Result<TNext, TE>.Err(_error!);

    public Result<TNext, TE> AndThen<TNext>(Func<T, Result<TNext, TE>> bindFn) => Bind(bindFn);

    public TOut Match<TOut>(Func<T, TOut> ok, Func<TE, TOut> err) =>
        IsOk ? ok(_value!) : err(_error!);

    public void Switch(Action<T> onOk, Action<TE> onErr)
    {
        if (IsOk) onOk(_value!);
        else onErr(_error!);
    }


    public bool IsOkAnd(Func<T, bool> predicate) => IsOk && predicate(_value!);

    public bool IsErrAnd(Func<TE, bool> predicate) => !IsOk && predicate(_error!);

    public override string ToString() => IsOk ? "Ok" : "Err";

    public bool Equals(Result<T, TE> other) => IsOk == other.IsOk &&
                                               (IsOk
                                                   ? EqualityComparer<T?>.Default.Equals(_value, other._value)
                                                   : EqualityComparer<TE>.Default.Equals(_error, other._error));

    public override bool Equals(object? obj) => obj is Result<T, TE> other && Equals(other);

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

    public static bool operator ==(Result<T, TE> left, Result<T, TE> right) => left.Equals(right);
    public static bool operator !=(Result<T, TE> left, Result<T, TE> right) => !left.Equals(right);
}

public static class ResultExtensions
{
    public static void IgnoreResult<T, TE>(this Result<T, TE> result) where TE : notnull
    {
    }
}