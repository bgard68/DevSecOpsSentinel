namespace DevSecOpsSentinel.Api.Security;

public sealed class ApiSecurityOptions
{
    public const string SectionName = "Security";
    public const string DisabledMode = "Disabled";
    public const string RequiredMode = "Required";

    public string Mode { get; init; } = DisabledMode;
    public string ApiKey { get; init; } = string.Empty;
    public string HeaderName { get; init; } = "X-API-Key";
    public string[] AllowedOrigins { get; init; } = [];

    public bool IsRequired =>
        string.Equals(
            Mode,
            RequiredMode,
            StringComparison.OrdinalIgnoreCase);

    public void Validate(string environmentName)
    {
        if (!IsRequired)
        {
            if (string.Equals(
                environmentName,
                "Production",
                StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "Security:Mode must be Required in Production.");
            }

            return;
        }

        if (string.IsNullOrWhiteSpace(ApiKey) ||
            ApiKey.Length < 32)
        {
            throw new InvalidOperationException(
                "Security:ApiKey must contain at least 32 characters when Security:Mode is Required.");
        }

        if (string.IsNullOrWhiteSpace(HeaderName))
        {
            throw new InvalidOperationException(
                "Security:HeaderName is required.");
        }
    }
}
