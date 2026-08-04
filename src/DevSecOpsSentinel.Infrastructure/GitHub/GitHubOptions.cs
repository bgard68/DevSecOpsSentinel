namespace DevSecOpsSentinel.Infrastructure.GitHub;

public sealed class GitHubOptions
{
    public const string SectionName = "GitHub";

    public bool Enabled { get; init; }
    public long AppId { get; init; }
    public long InstallationId { get; init; }
    public string PrivateKeyPath { get; init; } = string.Empty;
    public string ApiBaseUrl { get; init; } = "https://api.github.com";
    public string[] AllowedRepositories { get; init; } = [];

    public bool IsConfigured =>
        Enabled &&
        AppId > 0 &&
        InstallationId > 0 &&
        !string.IsNullOrWhiteSpace(PrivateKeyPath) &&
        File.Exists(PrivateKeyPath) &&
        AllowedRepositories.Length > 0;

    public bool IsAllowed(string owner, string repository) =>
        AllowedRepositories.Contains(
            $"{owner}/{repository}",
            StringComparer.OrdinalIgnoreCase);
}
