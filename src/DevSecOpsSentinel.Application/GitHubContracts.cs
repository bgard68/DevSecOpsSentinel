namespace DevSecOpsSentinel.Application;

public sealed record GitHubRepositorySummary(
    string Owner,
    string Name,
    string FullName,
    string DefaultBranch,
    bool IsPrivate,
    string HtmlUrl);

public sealed record GitHubWorkflowSummary(
    string Name,
    string Path,
    string Sha,
    string HtmlUrl);

public sealed record GitHubWorkflowFile(
    string Owner,
    string Repository,
    string DefaultBranch,
    string Path,
    string Sha,
    string Content,
    string HtmlUrl,
    DateTimeOffset RetrievedAtUtc);

public sealed record GitHubConnectionStatus(
    bool Enabled,
    bool Configured,
    bool Connected,
    string Mode,
    int AllowedRepositoryCount,
    string? Message);

public interface IGitHubRepositoryReader
{
    Task<IReadOnlyList<GitHubRepositorySummary>> GetRepositoriesAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<GitHubWorkflowSummary>> GetWorkflowsAsync(
        string owner,
        string repository,
        CancellationToken cancellationToken);

    Task<GitHubWorkflowFile?> GetWorkflowAsync(
        string owner,
        string repository,
        string path,
        string? reference,
        CancellationToken cancellationToken);
}

public interface IGitHubInstallationTokenProvider
{
    Task<string> GetTokenAsync(CancellationToken cancellationToken);
}
