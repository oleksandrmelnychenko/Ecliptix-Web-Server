namespace Ecliptix.Domain.Utilities;

public static class ResultExtensions
{
    public static void IgnoreResult<T, TE>(this Result<T, TE> result) where TE : notnull
    {
    }

    public static async Task<Result<TNextSuccess, TFailure>> BindAsync<TSuccess, TNextSuccess, TFailure>(
        this Task<Result<TSuccess, TFailure>> task,
        Func<TSuccess, Task<Result<TNextSuccess, TFailure>>> func)
    {
        Result<TSuccess, TFailure> result = await task;
        if (result.IsErr) return Result<TNextSuccess, TFailure>.Err(result.UnwrapErr());

        return await func(result.Unwrap());
    }
}