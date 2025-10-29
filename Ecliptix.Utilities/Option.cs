namespace Ecliptix.Utilities;

public readonly record struct Option<T>
{
    private Option(bool isSome, T? value)
    {
        IsSome = isSome;
        Value = value;
    }

    public bool IsSome { get; }
    public T? Value { get; }

    public static Option<T> None => new(false, default);

    public static Option<T> Some(T value)
    {
        return value is null ? throw new ArgumentNullException(nameof(value)) : new Option<T>(true, value);
    }

    public TResult Match<TResult>(Func<T, TResult> onSome, Func<TResult> onNone)
    {
        return IsSome ? onSome(Value!) : onNone();
    }
}
