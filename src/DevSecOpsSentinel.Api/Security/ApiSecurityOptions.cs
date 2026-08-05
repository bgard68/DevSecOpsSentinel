namespace DevSecOpsSentinel.Api.Security;

public sealed class ApiSecurityOptions
{
    public const string SectionName = "Security";
    public const string DisabledMode = "Disabled";
    public const string RequiredMode = "Required";

    /// <summary>
    /// Deterministic analysis is open to anyone; the key still guards the
    /// endpoints that borrow a credential or spend money.
    ///
    /// Rule evaluation is local computation over text — it reaches nothing,
    /// spends nothing and stores nothing — so there is no case for a key in
    /// front of it, and a public demonstration that nobody can run demonstrates
    /// nothing. GitHub reads use the App's private key, and Live explanations
    /// use the OpenAI key, so those stay behind it.
    /// </summary>
    public const string PublicMode = "Public";

    public string Mode { get; init; } = RequiredMode;
    public string ApiKey { get; init; } = string.Empty;
    public string HeaderName { get; init; } = "X-API-Key";
    public string[] AllowedOrigins { get; init; } = [];

    public bool IsRequired =>
        string.Equals(
            Mode,
            RequiredMode,
            StringComparison.OrdinalIgnoreCase);

    public bool IsPublicScanner =>
        string.Equals(
            Mode,
            PublicMode,
            StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Whether a key is configured and meaningful. True for both Required and
    /// Public: Public still guards the privileged endpoints with it.
    /// </summary>
    public bool UsesApiKey => IsRequired || IsPublicScanner;

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

        if (!UsesApiKey)
        {
            return allowsDisabled;
        }

        return !string.IsNullOrWhiteSpace(ApiKey) &&
            ApiKey.Length >= 32 &&
            !string.IsNullOrWhiteSpace(HeaderName);
    }

    public string GetValidationFailure(string environmentName)
    {
        if (!UsesApiKey &&
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
                "Security:Mode must be Required or Public outside Development and Testing.";
        }

        if (UsesApiKey &&
            (string.IsNullOrWhiteSpace(ApiKey) ||
             ApiKey.Length < 32))
        {
            return
                $"Security:ApiKey must contain at least 32 characters when Security:Mode is {Mode}.";
        }

        if (UsesApiKey &&
            string.IsNullOrWhiteSpace(HeaderName))
        {
            return "Security:HeaderName is required.";
        }

        return "API security configuration is invalid.";
    }
}
