namespace Ecliptix.Domain.Memberships;

public record PasswordPolicy(
    int MinLength = 8,
    bool RequireLowercase = true,
    bool RequireUppercase = true,
    bool RequireDigit = true,
    bool RequireSpecialChar = true,
    string AllowedSpecialChars = "@$!%*?&",
    bool EnforceAllowedCharsOnly = false)
{
    public static PasswordPolicy Default => new();
}