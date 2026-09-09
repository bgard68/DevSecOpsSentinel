using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using DevSecOpsSentinel.Application;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace DevSecOpsSentinel.Api.Integration.Tests;

/// <summary>
/// The /api/github surface with the reader stubbed: allowlist refusals, the
/// status ladder, analysis of retrieved content — every branch that previously
/// only ran against the real GitHub App.
/// </summary>
public sealed class GitHubEndpointTests : IClassFixture<GitHubEndpointTests.ConfiguredFactory>
{
    private const string VulnerableYaml = "name: CI\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n";

    private readonly HttpClient _client;

    public GitHubEndpointTests(ConfiguredFactory factory) => _client = factory.CreateClient();

    [Fact]
    public async Task GetStatus_ReaderAnswers_ReportsConnected()
    {
        JsonElement status = await Get("/api/github/status");

        Assert.True(status.GetProperty("connected").GetBoolean(), status.GetRawText());
        Assert.Equal("ReadOnly", status.GetProperty("mode").GetString());
    }

    [Fact]
    public async Task GetRepositories_ReaderAlreadyFiltered_ReturnsOnlyAllowlistedEntries()
    {
        HttpResponseMessage response = await _client.GetAsync("/api/github/repositories");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        JsonElement items = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(1, items.GetArrayLength());
        Assert.Equal("octo/Sandbox", items[0].GetProperty("fullName").GetString());
    }

    [Fact]
    public async Task GetRepository_OutsideTheAllowlist_ReturnsForbidden()
    {
        HttpResponseMessage response =
            await _client.GetAsync("/api/github/repositories/octo/Other/workflows");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task GetWorkflows_AllowlistedRepository_ReturnsTheWorkflowList()
    {
        JsonElement items = await Get("/api/github/repositories/octo/Sandbox/workflows");

        Assert.Equal(1, items.GetArrayLength());
        Assert.Equal(".github/workflows/ci.yml", items[0].GetProperty("path").GetString());
    }

    [Fact]
    public async Task GetWorkflowContent_KnownAndMissingPaths_ReturnsFileThenNotFound()
    {
        JsonElement file = await Get(
            "/api/github/repositories/octo/Sandbox/workflows/content?path=.github/workflows/ci.yml");
        Assert.Equal(VulnerableYaml, file.GetProperty("content").GetString());

        HttpResponseMessage missing = await _client.GetAsync(
            "/api/github/repositories/octo/Sandbox/workflows/content?path=.github/workflows/nope.yml");
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
    }

    [Fact]
    public async Task AnalyzeRepositoryWorkflow_RetrievedFile_RunsTheDeterministicRules()
    {
        HttpResponseMessage response = await _client.PostAsJsonAsync(
            "/api/github/repositories/octo/Sandbox/analyze",
            new { path = ".github/workflows/ci.yml", useAi = false });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        string body = await response.Content.ReadAsStringAsync();
        Assert.Contains("GHA001", body);
    }

    [Fact]
    public async Task AnalyzeRepositoryWorkflow_OutsideTheAllowlist_ReturnsForbidden()
    {
        HttpResponseMessage response = await _client.PostAsJsonAsync(
            "/api/github/repositories/octo/Other/analyze",
            new { path = ".github/workflows/ci.yml", useAi = false });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task AnalyzeRepositoryWorkflow_MissingWorkflow_ReturnsNotFound()
    {
        HttpResponseMessage response = await _client.PostAsJsonAsync(
            "/api/github/repositories/octo/Sandbox/analyze",
            new { path = ".github/workflows/nope.yml", useAi = false });

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task AnalyzeRepositoryWorkflow_WithAiRequested_ReturnsTheMockExplanation()
    {
        HttpResponseMessage response = await _client.PostAsJsonAsync(
            "/api/github/repositories/octo/Sandbox/analyze",
            new { path = ".github/workflows/ci.yml", useAi = true });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        string body = await response.Content.ReadAsStringAsync();
        Assert.Contains("explanation", body);
    }

    [Fact]
    public async Task GetStatus_ReaderThrows_DegradesToNotConnected()
    {
        using BrokenFactory broken = new();
        using HttpClient client = broken.CreateClient();

        HttpResponseMessage response = await client.GetAsync("/api/github/status");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        JsonElement status = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.False(status.GetProperty("connected").GetBoolean());
    }

    private async Task<JsonElement> Get(string path)
    {
        HttpResponseMessage response = await _client.GetAsync(path);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
    }

    private static DevSecOpsSentinel.Infrastructure.GitHub.GitHubOptions ConfiguredOptions() => new()
    {
        Enabled = true,
        AppId = 1,
        InstallationId = 2,
        PrivateKey = "-----BEGIN key",
        AllowedRepositories = ["octo/Sandbox"]
    };

    private static Dictionary<string, string?> ConfiguredGitHub() => new()
    {
        ["OpenAI:Mode"] = "Mock",
        ["OpenAI:ApiKey"] = string.Empty,
        ["GitHub:Enabled"] = "true",
        ["GitHub:AppId"] = "1",
        ["GitHub:InstallationId"] = "2",
        ["GitHub:PrivateKey"] = "-----BEGIN key",
        ["GitHub:AllowedRepositories:0"] = "octo/Sandbox",
        ["GitHub:ResolveActionReferences"] = "false",
        ["Security:Mode"] = "Disabled",
        ["Security:ApiKey"] = string.Empty
    };

    public sealed class ConfiguredFactory : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(ConfiguredGitHub()));
            builder.ConfigureServices(services =>
            {
                // Program reads GitHubOptions from configuration before Build(), so factory
                // configuration lands too late for it. The endpoints resolve the options
                // from DI, so replacing the singleton is the supported seam.
                services.RemoveAll<DevSecOpsSentinel.Infrastructure.GitHub.GitHubOptions>();
                services.AddSingleton(ConfiguredOptions());
                services.RemoveAll<IGitHubRepositoryReader>();
                services.AddSingleton<IGitHubRepositoryReader>(new StubReader(throwOnList: false));
            });
        }
    }

    private sealed class BrokenFactory : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(ConfiguredGitHub()));
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DevSecOpsSentinel.Infrastructure.GitHub.GitHubOptions>();
                services.AddSingleton(ConfiguredOptions());
                services.RemoveAll<IGitHubRepositoryReader>();
                services.AddSingleton<IGitHubRepositoryReader>(new StubReader(throwOnList: true));
            });
        }
    }

    private sealed class StubReader(bool throwOnList) : IGitHubRepositoryReader
    {
        public Task<IReadOnlyList<GitHubRepositorySummary>> GetRepositoriesAsync(
            CancellationToken cancellationToken) =>
            throwOnList
                ? Task.FromException<IReadOnlyList<GitHubRepositorySummary>>(
                    new HttpRequestException("GitHub unreachable"))
                : Task.FromResult<IReadOnlyList<GitHubRepositorySummary>>(
                [
                    new GitHubRepositorySummary(
                        "octo", "Sandbox", "octo/Sandbox", "main", true, "https://github.test/octo/Sandbox")
                ]);

        public Task<IReadOnlyList<GitHubWorkflowSummary>> GetWorkflowsAsync(
            string owner, string repository, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<GitHubWorkflowSummary>>(
            [
                new GitHubWorkflowSummary("ci.yml", ".github/workflows/ci.yml", "abc", "https://github.test/ci")
            ]);

        public Task<GitHubWorkflowFile?> GetWorkflowAsync(
            string owner, string repository, string path, string? reference,
            CancellationToken cancellationToken) =>
            Task.FromResult<GitHubWorkflowFile?>(path.EndsWith("ci.yml", StringComparison.Ordinal)
                ? new GitHubWorkflowFile(
                    owner, repository, reference ?? "main", path, "abc",
                    VulnerableYaml, "https://github.test/ci", DateTimeOffset.UnixEpoch)
                : null);
    }
}
