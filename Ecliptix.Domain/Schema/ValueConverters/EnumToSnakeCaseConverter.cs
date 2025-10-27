using System.Text;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Ecliptix.Domain.Schema.ValueConverters;

public class EnumToSnakeCaseConverter<TEnum>() : ValueConverter<TEnum, string>(
    enumValue => ConvertToSnakeCase(enumValue.ToString()),
    stringValue => ParseFromSnakeCase(stringValue))
    where TEnum : struct, Enum
{
    private static string ConvertToSnakeCase(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }

        StringBuilder result = new();
        result.Append(char.ToLowerInvariant(value[0]));

        for (int i = 1; i < value.Length; i++)
        {
            char c = value[i];
            if (char.IsUpper(c))
            {
                result.Append('_');
                result.Append(char.ToLowerInvariant(c));
            }
            else
            {
                result.Append(c);
            }
        }

        return result.ToString();
    }

    private static TEnum ParseFromSnakeCase(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return default;
        }

        StringBuilder result = new StringBuilder();
        bool capitalizeNext = true;

        foreach (char c in value)
        {
            if (c == '_')
            {
                capitalizeNext = true;
            }
            else
            {
                result.Append(capitalizeNext ? char.ToUpperInvariant(c) : c);
                capitalizeNext = false;
            }
        }

        string pascalCase = result.ToString();

        if (Enum.TryParse<TEnum>(pascalCase, true, out TEnum enumValue))
        {
            return enumValue;
        }

        throw new InvalidOperationException(
            $"Cannot convert '{value}' to {typeof(TEnum).Name}. PascalCase equivalent: '{pascalCase}'");
    }
}
