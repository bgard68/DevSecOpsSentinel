namespace DevSecOpsSentinel.Api.Security;

public sealed class ApiSecurityOptions
{
    public const string SectionName = "Security";
    public const string DisabledMode = "Disabled";
    public const string RequiredMode = "Required";

    public string Mode { get; init; } = RequiredMode;
    public string ApiKey { get; init; } = string.Empty;
    public string HeaderName { get; init; } = "X-API-Key";
    public string[] AllowedOrigins { get; init; } = [];

    public bool IsRequired =>
        string.Equals(
            Mode,
            RequiredMode,
            StringComparison.OrdinalIgnoreCase);

    public bool IsValidForEnvironment(string environmentName)
    {
        bool allowsDisabled =
            string.Equals(
                environmentName,
                "Development",
                StringComparison.OrdinalIgnoreCase) ||
            string.Equals(
                environmentName,
                "Testing",
                StringComparison.OrdinalIgnoreCase);

        if (!IsRequired)
        {
            return allowsDisabled;
        }

        return !string.IsNullOrWhiteSpace(ApiKey) &&
            ApiKey.Length >= 32 &&
            !string.IsNullOrWhiteSpace(HeaderName);
    }

    public string GetValidationFailure(string environmentName)
    {
        if (!IsRequired &&
            !string.Equals(
                environmentName,
                "Development",
                StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(
                environmentName,
                "Testing",
                StringComparison.OrdinalIgnoreCase))
        {
            return
                "Security:Mode must be Required outside Development and Testing.";
        }

        if (IsRequired &&
            (string.IsNullOrWhiteSpace(ApiKey) ||
             ApiKey.Length < 32))
        {
            return
                "Security:ApiKey must contain at least 32 characters when Security:Mode is Required.";
        }

        if (IsRequired &&
            string.IsNullOrWhiteSpace(HeaderName))
        {
            return "Security:HeaderName is required.";
        }

        return "API security configuration is invalid.";
    }
}
