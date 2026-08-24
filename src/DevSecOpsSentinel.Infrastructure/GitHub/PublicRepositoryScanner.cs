using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace DevSecOpsSentinel.Infrastructure.GitHub;

/// <summary>
/// Fetches a public repository's workflows without credentials and runs the
/// deterministic analysis over them.
///
/// The quota is the design constraint. GitHub allows 60 unauthenticated API
/// requests per hour per source address, shared by every visitor this host
/// serves — so the directory listing is the only call that spends it. File
/// bodies come from raw.githubusercontent.com, which is not metered, and every
/// outcome is cached, including the failures: a repository that does not exist
/// is an answer worth remembering too, or one stranger retrying a typo drains
/// the hour for everyone.
/// </summary>
public sealed partial class PublicRepositoryScanner(
    IHttpClientFactory httpClientFactory,
    IWorkflowAnalysisService analysisService,
    IMemoryCache cache,
    TimeProvider clock,
    ILogger<PublicRepositoryScanner> logger) : IPublicRepositoryScanner
{
    /// <summary>
    /// Enough for the overwhelming majority of repositories (the field scan's
    /// median was well under it) while bounding the work a single request can
    /// cause. Files beyond the cap are counted, not silently dropped.
    /// </summary>
    internal const int MaximumWorkflowFiles = 30;

    /// <summary>Matches the request-body limit the analyze endpoint enforces.</summary>
    internal const int MaximumWorkflowCharacters = 100_000;

    private static readonly TimeSpan SuccessTtl = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan NotFoundTtl = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan QuotaTtl = TimeSpan.FromSeconds(90);

    [GeneratedRegex("^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")]
    private static partial Regex OwnerPattern();

    [GeneratedRegex(@"^[A-Za-z0-9._-]{1,100}$")]
    private static partial Regex RepositoryPattern();

    public async Task<PublicScanResult> ScanAsync(
        string owner,
        string repository,
        CancellationToken cancellationToken)
    {
        DateTimeOffset now = clock.GetUtcNow();

        // Validated before anything else touches them: these two strings become a
        // URL path on a host we chose, and the pattern is what keeps them from
        // becoming anything more interesting than a repository name.
        if (!OwnerPattern().IsMatch(owner) || !RepositoryPattern().IsMatch(repository))
        {
            return PublicScanResult.Failure(
                owner,
                repository,
                PublicScanStatus.InvalidName,
                "Owner and repository must be plain GitHub names.",
                now);
        }

        string key = $"public-scan:{owner.ToLowerInvariant()}/{repository.ToLowerInvariant()}";
        if (cache.TryGetValue(key, out PublicScanResult? cached) && cached is not null)
        {
            return cached with { FromCache = true };
        }

        PublicScanResult result = await FetchAndAnalyzeAsync(owner, repository, now, cancellationToken);

        cache.Set(key, result, result.Status switch
        {
            PublicScanStatus.Completed or PublicScanStatus.NoWorkflows => SuccessTtl,
            PublicScanStatus.QuotaExhausted => QuotaTtl,
            _ => NotFoundTtl
        });

        return result;
    }

    private async Task<PublicScanResult> FetchAndAnalyzeAsync(
        string owner,
        string repository,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        HttpClient client = httpClientFactory.CreateClient("GitHubPublic");

        string listingPath =
            $"/repos/{Uri.EscapeDataString(owner)}/{Uri.EscapeDataString(repository)}/contents/.github/workflows";

        using HttpResponseMessage listing = await client.GetAsync(listingPath, cancellationToken);

        if (IsQuotaExhausted(listing))
        {
            logger.LogWarning(
                "GitHub unauthenticated quota exhausted while listing workflows.");
            return PublicScanResult.Failure(
                owner,
                repository,
                PublicScanStatus.QuotaExhausted,
                "GitHub limits anonymous lookups per hour for this host, and the "
                + "budget is spent. Cached results are unaffected; try again shortly.",
                now);
        }

        if (listing.StatusCode == HttpStatusCode.NotFound)
        {
            // A missing repository and a repository with no .github/workflows both
            // 404 here. One more request could tell them apart, but it would double
            // the quota cost of every typo, so the listing's answer is refined only
            // when it succeeds and the distinction is reported honestly otherwise.
            return PublicScanResult.Failure(
                owner,
                repository,
                PublicScanStatus.RepositoryNotFound,
                "No public repository with workflows was found under that name. "
                + "Private repositories are invisible to an anonymous scan.",
                now);
        }

        if (!listing.IsSuccessStatusCode)
        {
            logger.LogWarning(
                "GitHub listing returned {StatusCode}.",
                (int)listing.StatusCode);
            return PublicScanResult.Failure(
                owner,
                repository,
                PublicScanStatus.GitHubUnavailable,
                $"GitHub answered {(int)listing.StatusCode} for the workflow listing.",
                now);
        }

        ContentItem[] items =
            await listing.Content.ReadFromJsonAsync<ContentItem[]>(cancellationToken) ?? [];

        ContentItem[] workflows =
        [
            .. items
                .Where(item => string.Equals(item.Type, "file", StringComparison.OrdinalIgnoreCase))
                .Where(item =>
                    item.Name.EndsWith(".yml", StringComparison.OrdinalIgnoreCase) ||
                    item.Name.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase))
                .Where(item => !string.IsNullOrWhiteSpace(item.DownloadUrl))
                .OrderBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
        ];

        if (workflows.Length == 0)
        {
            return PublicScanResult.Failure(
                owner,
                repository,
                PublicScanStatus.NoWorkflows,
                "The repository exists but .github/workflows contains no workflow files.",
                now);
        }

        int skipped = 0;
        List<PublicScanFile> files = [];

        foreach (ContentItem item in workflows)
        {
            if (files.Count >= MaximumWorkflowFiles || item.Size > MaximumWorkflowCharacters)
            {
                skipped++;
                continue;
            }

            // download_url points at raw.githubusercontent.com, which does not
            // count against the API quota — the reason one scan costs one metered
            // request no matter how many workflows the repository has.
            string content = await client.GetStringAsync(item.DownloadUrl, cancellationToken);
            if (content.Length > MaximumWorkflowCharacters)
            {
                skipped++;
                continue;
            }

            WorkflowAnalysisResult analysis = await analysisService.AnalyzeAsync(
                new WorkflowDocument(item.Name, content),
                cancellationToken);

            files.Add(new PublicScanFile(item.Name, item.HtmlUrl, analysis));
        }

        return new PublicScanResult(
            owner,
            repository,
            PublicScanStatus.Completed,
            Detail: null,
            files,
            skipped,
            now,
            FromCache: false);
    }

    private static bool IsQuotaExhausted(HttpResponseMessage response)
    {
        if (response.StatusCode is not (HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests))
        {
            return false;
        }

        // GitHub reports quota exhaustion as 403 with a zeroed remaining-count
        // header; a plain 403 without it is something else and falls through to
        // the generic unavailable path via the success-status check.
        return response.Headers.TryGetValues("X-RateLimit-Remaining", out IEnumerable<string>? values) &&
               values.FirstOrDefault() == "0" ||
               response.StatusCode == HttpStatusCode.TooManyRequests;
    }

    private sealed record ContentItem(
        [property: JsonPropertyName("name")] string Name,
        [property: JsonPropertyName("type")] string Type,
        [property: JsonPropertyName("size")] long Size,
        [property: JsonPropertyName("html_url")] string HtmlUrl,
        [property: JsonPropertyName("download_url")] string? DownloadUrl);
}
