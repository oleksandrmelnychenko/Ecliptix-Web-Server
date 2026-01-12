using Ecliptix.SharedKernel;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing;

internal static class ResultAsyncExtensions
{
    public static async Task<Result<TNext, TE>> BindAsync<T, TNext, TE>(
        this Result<T, TE> result,
        Func<T, Task<Result<TNext, TE>>> bindFn) where TE : notnull
    {
        return result.IsOk
            ? await bindFn(result.Unwrap())
            : Result<TNext, TE>.Err(result.UnwrapErr());
    }

    public static async Task<Result<TNext, TE>> BindAsync<T, TNext, TE>(
        this Task<Result<T, TE>> resultTask,
        Func<T, Task<Result<TNext, TE>>> bindFn) where TE : notnull
    {
        Result<T, TE> result = await resultTask;
        return result.IsOk
            ? await bindFn(result.Unwrap())
            : Result<TNext, TE>.Err(result.UnwrapErr());
    }

    public static async Task<Result<TNext, TE>> Bind<T, TNext, TE>(
        this Task<Result<T, TE>> resultTask,
        Func<T, Result<TNext, TE>> bindFn) where TE : notnull
    {
        Result<T, TE> result = await resultTask;
        return result.IsOk
            ? bindFn(result.Unwrap())
            : Result<TNext, TE>.Err(result.UnwrapErr());
    }

    public static async Task<TOut> MatchAsync<T, TE, TOut>(
        this Task<Result<T, TE>> resultTask,
        Func<T, TOut> ok,
        Func<TE, TOut> err)
    {
        Result<T, TE> result = await resultTask;
        return result.Match(ok, err);
    }
}
