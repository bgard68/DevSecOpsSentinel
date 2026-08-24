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
    Task<IReadOnlyList<GitHubRepositorySummary>> GetRepositoriesAsync(
        CancellationToken cancellationToken);

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

public enum ActionReferenceResolutionStatus
{
    Resolved,
    Unsupported,
    NotFound,
    RateLimited,
    AuthenticationFailed,
    NetworkUnavailable,
    Failed
}

public sealed record ActionReferenceResolutionResult(
    ActionReferenceResolutionStatus Status,
    string? CommitSha,
    string Message)
{
    public bool IsResolved =>
        Status == ActionReferenceResolutionStatus.Resolved &&
        !string.IsNullOrWhiteSpace(CommitSha);
}

public interface IWorkflowActionReferenceResolver
{
    Task<ActionReferenceResolutionResult> ResolveAsync(
        string actionReference,
        CancellationToken cancellationToken);
}

// Moved here from Infrastructure. The Api layer injects this into the readiness endpoint, so
// leaving it beside its implementation had the outer layer depending on an abstraction the
// outer layer also owned — the one place in this project where that was true. Every other
// contract is declared by the layer that needs it and implemented further out; this one now
// matches.

/// <summary>
/// Supplies the GitHub App private key, from configuration or from a file.
///
/// A file path is workable on a developer machine and unworkable on a hosted
/// platform: App Service application settings and Key Vault references deliver a
/// value, not a file. Reading the key only from disk is what stopped this
/// application being deployable.
///
/// Configuration wins when both are present, so a deployment cannot be
/// accidentally served by a stale file left on the host.
/// </summary>
public interface IGitHubPrivateKeySource
{
    /// <summary>
    /// True when a key can be obtained. Answers the readiness probe without
    /// throwing, and without holding key material to find out.
    /// </summary>
    bool IsAvailable { get; }

    /// <summary>Describes where the key comes from. Contains no key material.</summary>
    string Description { get; }

    /// <summary>The PEM text. Throws when no key is configured.</summary>
    string ReadPem();
}
