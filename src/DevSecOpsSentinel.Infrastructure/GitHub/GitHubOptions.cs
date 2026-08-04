namespace DevSecOpsSentinel.Infrastructure.GitHub;

public sealed class GitHubOptions
{
    public const string SectionName = "GitHub";

    public bool Enabled { get; init; }
    public bool ResolveActionReferences { get; init; }
    public long AppId { get; init; }
    public long InstallationId { get; init; }
    /// <summary>
    /// Path to the App private key. Convenient locally; unusable on a hosted
    /// platform, which delivers configuration values rather than files.
    /// </summary>
    public string PrivateKeyPath { get; init; } = string.Empty;

    /// <summary>
    /// The App private key itself, as PEM text or base64-encoded PEM. This is
    /// what an App Service application setting or a Key Vault reference
    /// supplies, and it takes precedence over <see cref="PrivateKeyPath"/>.
    /// </summary>
    public string PrivateKey { get; init; } = string.Empty;

    public string ApiBaseUrl { get; init; } = "https://api.github.com";
    public string[] AllowedRepositories { get; init; } = [];

    /// <summary>
    /// Whether a key is nominated. Whether it can actually be read is
    /// <see cref="IGitHubPrivateKeySource.IsAvailable"/>, because that requires
    /// touching the filesystem and this is a pure configuration check.
    /// </summary>
    public bool HasPrivateKeySetting =>
        !string.IsNullOrWhiteSpace(PrivateKey) ||
        !string.IsNullOrWhiteSpace(PrivateKeyPath);

    public bool IsConfigured =>
        Enabled &&
        AppId > 0 &&
        InstallationId > 0 &&
        HasPrivateKeySetting &&
        AllowedRepositories.Length > 0;

    public bool IsAllowed(string owner, string repository) =>
        AllowedRepositories.Contains(
            $"{owner}/{repository}",
            StringComparer.OrdinalIgnoreCase);
}
