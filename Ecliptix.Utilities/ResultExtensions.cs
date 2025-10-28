namespace Ecliptix.Utilities;

public static class ResultExtensions
{
    public static void IgnoreResult<T, TE>(this Result<T, TE> result) where TE : notnull
    {
    }
}
