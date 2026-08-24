using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Application;

/// <summary>
/// Scan of a public repository's workflows, requested by name alone.
///
/// This is the one feature that makes an outbound call on behalf of an anonymous
/// visitor, so its boundaries are the point: only api.github.com and
/// raw.githubusercontent.com are contacted, no credential is attached, nothing is
/// written, and results are cached so a popular repository costs one fetch rather
/// than one per visitor. Private repositories are invisible to it by construction —
/// an unauthenticated request cannot see them, which is the whole reason this needs
/// no allowlist while the GitHub App integration does.
/// </summary>
public interface IPublicRepositoryScanner
{
    Task<PublicScanResult> ScanAsync(
        string owner,
        string repository,
        CancellationToken cancellationToken);
}

public enum PublicScanStatus
{
    /// <summary>Workflows were fetched and analysed.</summary>
    Completed,

    /// <summary>The repository does not exist, or is private — indistinguishable
    /// without credentials, and deliberately reported the same way.</summary>
    RepositoryNotFound,

    /// <summary>The repository exists but has no workflow files.</summary>
    NoWorkflows,

    /// <summary>The owner or repository name is not a name GitHub could accept.</summary>
    InvalidName,

    /// <summary>GitHub's unauthenticated quota for this host is exhausted.</summary>
    QuotaExhausted,

    /// <summary>GitHub answered with something unexpected.</summary>
    GitHubUnavailable
}

/// <summary>One workflow file and what the deterministic rules made of it.</summary>
public sealed record PublicScanFile(
    string FileName,
    string HtmlUrl,
    WorkflowAnalysisResult Analysis);

public sealed record PublicScanResult(
    string Owner,
    string Repository,
    PublicScanStatus Status,
    string? Detail,
    IReadOnlyList<PublicScanFile> Files,
    int SkippedFiles,
    DateTimeOffset FetchedAtUtc,
    bool FromCache)
{
    public static PublicScanResult Failure(
        string owner,
        string repository,
        PublicScanStatus status,
        string detail,
        DateTimeOffset atUtc) =>
        new(owner, repository, status, detail, [], 0, atUtc, FromCache: false);
}
