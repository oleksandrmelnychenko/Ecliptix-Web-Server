namespace Ecliptix.Utilities;

public readonly record struct Option<T>
{
    private Option(bool hasValue, T? value)
    {
        HasValue = hasValue;
        Value = value;
    }

    public bool HasValue { get; }
    public T? Value { get; }

    public static Option<T> None => new(false, default);

    public static Option<T> Some(T value)
    {
        if (value is null) throw new ArgumentNullException(nameof(value));
        return new Option<T>(true, value);
    }

    public TResult Match<TResult>(Func<T, TResult> onSome, Func<TResult> onNone)
    {
        return HasValue ? onSome(Value!) : onNone();
    }
}