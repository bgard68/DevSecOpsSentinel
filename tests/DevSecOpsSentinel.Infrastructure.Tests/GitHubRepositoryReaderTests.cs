using System.Net;
using System.Text;
using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Infrastructure.GitHub;

namespace DevSecOpsSentinel.Infrastructure.Tests;

/// <summary>
/// The App-authenticated reader, faked at the HttpClient layer so the real request
/// pipeline runs: URL construction, the bearer token, the allowlist gates, the base64
/// decode. ADR-004 says this integration is read-only and allowlisted; the allowlist
/// half of that claim lives in this class and is pinned here.
/// </summary>
public sealed class GitHubRepositoryReaderTests
{
    private static GitHubOptions Options(params string[] allowed) => new()
    {
        Enabled = true,
        AppId = 1,
        InstallationId = 2,
        PrivateKey = "-----BEGIN key",
        AllowedRepositories = allowed,
        ApiBaseUrl = "https://api.github.test"
    };

    private sealed class FakeTokenProvider : IGitHubInstallationTokenProvider
    {
        public Task<string> GetTokenAsync(CancellationToken cancellationToken) =>
            Task.FromResult("installation-token");
    }

    private sealed class FakeHttp(Func<HttpRequestMessage, HttpResponseMessage> respond)
        : HttpMessageHandler, IHttpClientFactory
    {
        public List<HttpRequestMessage> Requests { get; } = [];

        public HttpClient CreateClient(string name) => new(this);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests.Add(request);
            return Task.FromResult(respond(request));
        }
    }

    private static HttpResponseMessage Json(string body, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    [Fact]
    public async Task Repositories_outside_the_allowlist_are_dropped_even_when_the_installation_grants_them()
    {
        // The installation and the allowlist are separate gates on purpose: someone
        // widening the App's installation must not silently widen this application.
        FakeHttp http = new(_ => Json("""
            { "repositories": [
                { "name": "Sandbox", "full_name": "octo/Sandbox", "default_branch": "main",
                  "private": true, "html_url": "https://github.test/octo/Sandbox",
                  "owner": { "login": "octo" } },
                { "name": "Other", "full_name": "octo/Other", "default_branch": "main",
                  "private": true, "html_url": "https://github.test/octo/Other",
                  "owner": { "login": "octo" } }
            ]}
            """));
        var reader = new GitHubRepositoryReader(http, Options("octo/Sandbox"), new FakeTokenProvider());

        IReadOnlyList<GitHubRepositorySummary> repositories =
            await reader.GetRepositoriesAsync(CancellationToken.None);

        Assert.Equal("octo/Sandbox", Assert.Single(repositories).FullName);
    }

    [Fact]
    public async Task Requests_carry_the_installation_token_and_the_api_version()
    {
        FakeHttp http = new(_ => Json("""{ "repositories": [] }"""));
        var reader = new GitHubRepositoryReader(http, Options("octo/Sandbox"), new FakeTokenProvider());

        await reader.GetRepositoriesAsync(CancellationToken.None);

        HttpRequestMessage request = Assert.Single(http.Requests);
        Assert.Equal("Bearer", request.Headers.Authorization?.Scheme);
        Assert.Equal("installation-token", request.Headers.Authorization?.Parameter);
        Assert.Contains("2022-11-28", request.Headers.GetValues("X-GitHub-Api-Version"));
    }

    [Fact]
    public async Task Workflow_listing_for_a_repository_outside_the_allowlist_is_refused_before_any_request()
    {
        FakeHttp http = new(_ => throw new InvalidOperationException("must not be called"));
        var reader = new GitHubRepositoryReader(http, Options("octo/Sandbox"), new FakeTokenProvider());

        await Assert.ThrowsAsync<UnauthorizedAccessException>(
            () => reader.GetWorkflowsAsync("octo", "Other", CancellationToken.None));
        Assert.Empty(http.Requests);
    }

    [Fact]
    public async Task Unconfigured_integration_is_refused_before_any_request()
    {
        FakeHttp http = new(_ => throw new InvalidOperationException("must not be called"));
        var reader = new GitHubRepositoryReader(http, new GitHubOptions(), new FakeTokenProvider());

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => reader.GetRepositoriesAsync(CancellationToken.None));
        Assert.Empty(http.Requests);
    }

    [Fact]
    public async Task Workflow_listing_returns_only_yaml_files_sorted_by_name()
    {
        FakeHttp http = new(_ => Json("""
            [
              { "name": "b.yml", "path": ".github/workflows/b.yml", "sha": "b1", "type": "file",
                "html_url": "https://github.test/b", "encoding": null, "content": null },
              { "name": "a.yaml", "path": ".github/workflows/a.yaml", "sha": "a1", "type": "file",
                "html_url": "https://github.test/a", "encoding": null, "content": null },
              { "name": "README.md", "path": ".github/workflows/README.md", "sha": "r1", "type": "file",
                "html_url": "https://github.test/r", "encoding": null, "content": null },
              { "name": "dir.yml", "path": ".github/workflows/dir.yml", "sha": "d1", "type": "dir",
                "html_url": "https://github.test/d", "encoding": null, "content": null }
            ]
            """));
        var reader = new GitHubRepositoryReader(http, Options("octo/Sandbox"), new FakeTokenProvider());

        IReadOnlyList<GitHubWorkflowSummary> workflows =
            await reader.GetWorkflowsAsync("octo", "Sandbox", CancellationToken.None);

        Assert.Equal(["a.yaml", "b.yml"], workflows.Select(workflow => workflow.Name).ToArray());
    }

    [Fact]
    public async Task A_missing_workflows_directory_is_an_empty_list_not_an_error()
    {
        FakeHttp http = new(_ => new HttpResponseMessage(HttpStatusCode.NotFound));
        var reader = new GitHubRepositoryReader(http, Options("octo/Sandbox"), new FakeTokenProvider());

        Assert.Empty(await reader.GetWorkflowsAsync("octo", "Sandbox", CancellationToken.None));
    }

    [Fact]
    public async Task Workflow_content_is_base64_decoded_with_the_reference_applied()
    {
        string yaml = "name: CI\non:\n  push:\n";
        string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(yaml));
        FakeHttp http = new(request => request.RequestUri!.Query.Contains("ref=feature")
            ? Json($$"""
                { "name": "ci.yml", "path": ".github/workflows/ci.yml", "sha": "abc", "type": "file",
                  "html_url": "https://github.test/ci", "encoding": "base64", "content": "{{encoded}}" }
                """)
            : new HttpResponseMessage(HttpStatusCode.NotFound));
        var reader = new GitHubRepositoryReader(http, Options("octo/Sandbox"), new FakeTokenProvider());

        GitHubWorkflowFile? file = await reader.GetWorkflowAsync(
            "octo", "Sandbox", ".github/workflows/ci.yml", "feature", CancellationToken.None);

        Assert.NotNull(file);
        Assert.Equal(yaml, file.Content);
        Assert.Equal("feature", file.DefaultBranch);
    }

    [Fact]
    public async Task Missing_workflow_content_is_null_not_an_error()
    {
        FakeHttp http = new(_ => new HttpResponseMessage(HttpStatusCode.NotFound));
        var reader = new GitHubRepositoryReader(http, Options("octo/Sandbox"), new FakeTokenProvider());

        Assert.Null(await reader.GetWorkflowAsync(
            "octo", "Sandbox", ".github/workflows/ci.yml", null, CancellationToken.None));
    }

    [Fact]
    public async Task Content_that_is_not_base64_is_rejected_loudly()
    {
        // Silent acceptance here would analyze garbage and report it as the repository's
        // workflow. Loud is correct.
        FakeHttp http = new(_ => Json("""
            { "name": "ci.yml", "path": "p", "sha": "s", "type": "file",
              "html_url": "u", "encoding": "utf-8", "content": "plain" }
            """));
        var reader = new GitHubRepositoryReader(http, Options("octo/Sandbox"), new FakeTokenProvider());

        await Assert.ThrowsAsync<InvalidOperationException>(() => reader.GetWorkflowAsync(
            "octo", "Sandbox", ".github/workflows/ci.yml", null, CancellationToken.None));
    }
}
