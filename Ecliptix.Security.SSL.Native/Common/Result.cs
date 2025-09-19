/*
 * Ecliptix Security SSL Native Library
 * Author: Oleksandr Melnychenko
 */

namespace Ecliptix.Security.SSL.Native.Common;

public class Result<TValue, TError>
{
    private readonly TValue? _value;
    private readonly TError? _error;
    public bool IsSuccess { get; }
    public bool IsError => !IsSuccess;

    private Result(TValue value)
    {
        _value = value;
        _error = default;
        IsSuccess = true;
    }

    private Result(TError error)
    {
        _value = default;
        _error = error;
        IsSuccess = false;
    }

    public static Result<TValue, TError> Ok(TValue value) => new(value);
    public static Result<TValue, TError> Err(TError error) => new(error);

    public TValue Value => IsSuccess ? _value! : throw new InvalidOperationException("Cannot access value of failed result");
    public TError Error => IsError ? _error! : throw new InvalidOperationException("Cannot access error of successful result");

    public TResult Match<TResult>(Func<TValue, TResult> onSuccess, Func<TError, TResult> onError)
    {
        return IsSuccess ? onSuccess(_value!) : onError(_error!);
    }

    public void Match(Action<TValue> onSuccess, Action<TError> onError)
    {
        if (IsSuccess)
            onSuccess(_value!);
        else
            onError(_error!);
    }
}

public struct Unit
{
    public static readonly Unit Value = new();
}