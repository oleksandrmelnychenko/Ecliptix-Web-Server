namespace Ecliptix.Utilities;

public static class ResultExtensions
{
    /// <summary>
    /// Intentionally discards the <see cref="Result{T,TE}"/> to make
    /// the intent clear and to suppress compiler/linter warnings about
    /// unhandled return values.
    /// </summary>
    /// <remarks>
    /// This method is intentionally empty. Its sole purpose is to
    /// be called in a fluent chain to terminate the chain and
    /// explicitly ignore the preceding result.
    /// </remarks>
    ///
    public static void IgnoreResult<T, TE>(this Result<T, TE> result) where TE : notnull
    {
        // Intentionally empty. See method summary
    }
}
