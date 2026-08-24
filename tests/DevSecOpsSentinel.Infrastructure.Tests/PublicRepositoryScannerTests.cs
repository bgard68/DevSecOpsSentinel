using System.Net;
using System.Text;
using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;
using DevSecOpsSentinel.Infrastructure;
using DevSecOpsSentinel.Infrastructure.GitHub;
using DevSecOpsSentinel.Infrastructure.Rules;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;

namespace DevSecOpsSentinel.Infrastructure.Tests;

public sealed class PublicRepositoryScannerTests : IDisposable
{
    private readonly MemoryCache _cache = new(new MemoryCacheOptions());

    public void Dispose() => _cache.Dispose();

    private const string VulnerableWorkflow = """
        name: CI
        on:
          push:
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
        """;

    [Fact]
    public async Task Scans_a_repository_and_reports_findings_per_file()
    {
        FakeGitHub github = new();
        github.Listing("octo", "app",
            File("ci.yml", VulnerableWorkflow.Length, "https://raw.test/ci.yml"));
        github.Raw("https://raw.test/ci.yml", VulnerableWorkflow);

        PublicScanResult result = await Scanner(github).ScanAsync("octo", "app", CancellationToken.None);

        Assert.Equal(PublicScanStatus.Completed, result.Status);
        PublicScanFile file = Assert.Single(result.Files);
        Assert.Equal("ci.yml", file.FileName);
        Assert.Contains(file.Analysis.Findings, finding => finding.RuleId == "GHA001");
        Assert.False(result.FromCache);
    }

    [Fact]
    public async Task Second_scan_of_the_same_repository_is_served_from_cache()
    {
        FakeGitHub github = new();
        github.Listing("octo", "app",
            File("ci.yml", VulnerableWorkflow.Length, "https://raw.test/ci.yml"));
        github.Raw("https://raw.test/ci.yml", VulnerableWorkflow);

        IPublicRepositoryScanner scanner = Scanner(github);
        await scanner.ScanAsync("octo", "app", CancellationToken.None);
        PublicScanResult second = await scanner.ScanAsync("OCTO", "APP", CancellationToken.None);

        // One metered listing request total — the second scan, even differently
        // cased, must not spend quota. That is the property the cache exists for.
        Assert.Equal(1, github.ListingRequests);
        Assert.True(second.FromCache);
    }

    [Fact]
    public async Task Missing_repository_is_not_found_and_the_failure_is_cached()
    {
        FakeGitHub github = new() { ListingStatus = HttpStatusCode.NotFound };

        IPublicRepositoryScanner scanner = Scanner(github);
        PublicScanResult first = await scanner.ScanAsync("octo", "gone", CancellationToken.None);
        await scanner.ScanAsync("octo", "gone", CancellationToken.None);

        Assert.Equal(PublicScanStatus.RepositoryNotFound, first.Status);
        // A typo retried must not spend the shared quota a second time.
        Assert.Equal(1, github.ListingRequests);
    }

    [Fact]
    public async Task Exhausted_quota_is_reported_as_such_not_as_a_missing_repository()
    {
        FakeGitHub github = new()
        {
            ListingStatus = HttpStatusCode.Forbidden,
            RateLimitRemaining = "0"
        };

        PublicScanResult result = await Scanner(github).ScanAsync("octo", "app", CancellationToken.None);

        Assert.Equal(PublicScanStatus.QuotaExhausted, result.Status);
    }

    [Theory]
    [InlineData("../etc", "app")]
    [InlineData("octo", "app/../../secrets")]
    [InlineData("", "app")]
    [InlineData("octo", "a b")]
    public async Task Names_that_are_not_plain_github_names_are_rejected_before_any_request(
        string owner,
        string repository)
    {
        FakeGitHub github = new();

        PublicScanResult result = await Scanner(github).ScanAsync(owner, repository, CancellationToken.None);

        Assert.Equal(PublicScanStatus.InvalidName, result.Status);
        // The whole point: a hostile name never becomes a URL.
        Assert.Equal(0, github.ListingRequests);
    }

    [Fact]
    public async Task Oversized_files_are_skipped_and_counted_rather_than_fetched()
    {
        FakeGitHub github = new();
        github.Listing("octo", "app",
            File("huge.yml", PublicRepositoryScanner.MaximumWorkflowCharacters + 1, "https://raw.test/huge.yml"),
            File("ci.yml", VulnerableWorkflow.Length, "https://raw.test/ci.yml"));
        github.Raw("https://raw.test/ci.yml", VulnerableWorkflow);

        PublicScanResult result = await Scanner(github).ScanAsync("octo", "app", CancellationToken.None);

        Assert.Equal(PublicScanStatus.Completed, result.Status);
        Assert.Single(result.Files);
        Assert.Equal(1, result.SkippedFiles);
        // The oversized file's body was never downloaded.
        Assert.DoesNotContain("https://raw.test/huge.yml", github.RawRequests);
    }

    [Fact]
    public async Task A_repository_with_a_workflows_directory_but_no_yml_files_reports_no_workflows()
    {
        FakeGitHub github = new();
        github.Listing("octo", "app", File("README.md", 10, "https://raw.test/readme"));

        PublicScanResult result = await Scanner(github).ScanAsync("octo", "app", CancellationToken.None);

        Assert.Equal(PublicScanStatus.NoWorkflows, result.Status);
    }

    private PublicRepositoryScanner Scanner(FakeGitHub github) =>
        new(
            github,
            new WorkflowAnalysisService(
                new WorkflowParser(),
                RuleDiscovery.All(),
                new WorkflowPatchGenerator(
                    new WorkflowParser(),
                    RuleDiscovery.All(),
                    new NeverResolvesActionReferenceResolver(),
                    new GitHubOptions())),
            _cache,
            TimeProvider.System,
            NullLogger<PublicRepositoryScanner>.Instance);

    private sealed class NeverResolvesActionReferenceResolver : IWorkflowActionReferenceResolver
    {
        public Task<ActionReferenceResolutionResult> ResolveAsync(
            string actionReference,
            CancellationToken cancellationToken) =>
            Task.FromResult(new ActionReferenceResolutionResult(
                ActionReferenceResolutionStatus.Failed,
                null,
                "Scanner tests do not resolve action references."));
    }

    private static string File(string name, long size, string downloadUrl) =>
        $$"""
        { "name": "{{name}}", "type": "file", "size": {{size}},
          "html_url": "https://github.test/{{name}}", "download_url": "{{downloadUrl}}" }
        """;

    /// <summary>
    /// The GitHub surface the scanner touches, faked at the HttpClient layer so the
    /// scanner's real request pipeline — URL construction included — is what is tested.
    /// </summary>
    private sealed class FakeGitHub : IHttpClientFactory
    {
        private readonly Dictionary<string, string> _raw = [];
        private string _listingBody = "[]";

        public HttpStatusCode ListingStatus { get; set; } = HttpStatusCode.OK;
        public string? RateLimitRemaining { get; set; }
        public int ListingRequests { get; private set; }
        public List<string> RawRequests { get; } = [];

        public void Listing(string owner, string repository, params string[] files) =>
            _listingBody = "[" + string.Join(",", files) + "]";

        public void Raw(string url, string content) => _raw[url] = content;

        public HttpClient CreateClient(string name) =>
            new(new Handler(this)) { BaseAddress = new Uri("https://api.github.test") };

        private sealed class Handler(FakeGitHub fake) : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request,
                CancellationToken cancellationToken)
            {
                // Ownership of these responses transfers to the caller: the scanner
                // disposes the listing via `using`, and GetStringAsync disposes the raw
                // response internally. Built in methods that return them directly so the
                // transfer is visible to analysis.
                string url = request.RequestUri!.ToString();
                return Task.FromResult(url.Contains("/contents/.github/workflows")
                    ? BuildListingResponse()
                    : BuildRawResponse(url));
            }

            private HttpResponseMessage BuildListingResponse()
            {
                fake.ListingRequests++;
                HttpResponseMessage response = new(fake.ListingStatus)
                {
                    Content = new StringContent(fake._listingBody, Encoding.UTF8, "application/json")
                };
                if (fake.RateLimitRemaining is not null)
                {
                    response.Headers.Add("X-RateLimit-Remaining", fake.RateLimitRemaining);
                }

                return response;
            }

            private HttpResponseMessage BuildRawResponse(string url)
            {
                fake.RawRequests.Add(url);
                return fake._raw.TryGetValue(url, out string? content)
                    ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(content) }
                    : new HttpResponseMessage(HttpStatusCode.NotFound);
            }
        }
    }
}
