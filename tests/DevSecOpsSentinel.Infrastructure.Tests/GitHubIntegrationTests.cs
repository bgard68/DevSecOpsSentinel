using DevSecOpsSentinel.Application;
using System.Security.Cryptography;
using System.Net;
using System.Text;
using System.Text.Json;
using DevSecOpsSentinel.Infrastructure.GitHub;

namespace DevSecOpsSentinel.Infrastructure.Tests;

public sealed class GitHubIntegrationTests
{
    [Fact]
    public void CreateJwt_ConfiguredAppId_ProducesAnRs256TokenWithThatIssuer()
    {
        string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string keyPath = Path.Combine(directory, "github-app.pem");

        try
        {
            using RSA rsa = RSA.Create(2048);
            File.WriteAllText(keyPath, rsa.ExportRSAPrivateKeyPem());
            var options = new GitHubOptions
            {
                Enabled = true,
                AppId = 12345,
                InstallationId = 67890,
                PrivateKeyPath = keyPath,
                AllowedRepositories = ["bgard68/DevSecOpsSentinel-Sandbox"]
            };

            string token = new GitHubAppJwtFactory(
                options,
                new GitHubPrivateKeySource(options))
                .CreateToken(DateTimeOffset.FromUnixTimeSeconds(1_800_000_000));

            string[] parts = token.Split('.');
            Assert.Equal(3, parts.Length);

            using JsonDocument header = JsonDocument.Parse(Decode(parts[0]));
            using JsonDocument payload = JsonDocument.Parse(Decode(parts[1]));
            Assert.Equal("RS256", header.RootElement.GetProperty("alg").GetString());
            Assert.Equal("12345", payload.RootElement.GetProperty("iss").GetString());
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Theory]
    [InlineData("bgard68", "DevSecOpsSentinel-Sandbox", true)]
    [InlineData("BGARD68", "devsecopssentinel-sandbox", true)]
    [InlineData("bgard68", "ToDoApp", false)]
    public void IsRepositoryAllowed_MixedCaseAndUnlistedNames_MatchesCaseInsensitivelyAndRestrictively(
        string owner,
        string repository,
        bool expected)
    {
        var options = new GitHubOptions
        {
            AllowedRepositories = ["bgard68/DevSecOpsSentinel-Sandbox"]
        };

        Assert.Equal(expected, options.IsAllowed(owner, repository));
    }


    [Fact]
    public async Task ResolveAsync_LightweightTagViaResolver_ReturnsTheCommitSha()
    {
        const string sha =
            "2222222222222222222222222222222222222222";

        HttpClient client = new(new StubHttpMessageHandler(
            HttpStatusCode.OK,
            $$"""
            {
              "object": {
                "type": "commit",
                "sha": "{{sha}}"
              }
            }
            """));

        GitHubActionReferenceResolver resolver = new(
            new StubHttpClientFactory(client),
            new GitHubOptions(),
            new StubTokenProvider());

        ActionReferenceResolutionResult resolved =
            await resolver.ResolveAsync(
                "actions/checkout@v4",
                CancellationToken.None);

        Assert.True(resolved.IsResolved);
        Assert.Equal(sha, resolved.CommitSha);
    }

    [Fact]
    public async Task ResolveAsync_UnresolvableReference_ReturnsNoCommitSha()
    {
        HttpClient client = new(new StubHttpMessageHandler(
            HttpStatusCode.NotFound,
            string.Empty));

        GitHubActionReferenceResolver resolver = new(
            new StubHttpClientFactory(client),
            new GitHubOptions(),
            new StubTokenProvider());

        ActionReferenceResolutionResult resolved =
            await resolver.ResolveAsync(
                "actions/checkout@not-real",
                CancellationToken.None);

        Assert.False(resolved.IsResolved);
        Assert.Equal(
            ActionReferenceResolutionStatus.NotFound,
            resolved.Status);
    }


    [Fact]
    public void IsConfigured_PrivateKeyFileMissing_StillReportsConfigured()
    {
        GitHubOptions options = new()
        {
            Enabled = true,
            AppId = 12345,
            InstallationId = 67890,
            PrivateKeyPath = Path.Combine(
                Path.GetTempPath(),
                Guid.NewGuid().ToString("N"),
                "missing.pem"),
            AllowedRepositories =
            [
                "bgard68/DevSecOpsSentinel-Sandbox"
            ]
        };

        Assert.True(options.IsConfigured);
        Assert.False(File.Exists(options.PrivateKeyPath));
    }

    private sealed class StubHttpClientFactory(
        HttpClient client) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => client;
    }

    private sealed class StubTokenProvider :
        IGitHubInstallationTokenProvider
    {
        public Task<string> GetTokenAsync(
            CancellationToken cancellationToken) =>
            Task.FromResult("unused");
    }

    private sealed class StubHttpMessageHandler(
        HttpStatusCode statusCode,
        string content) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            HttpResponseMessage response = new(statusCode)
            {
                Content = new StringContent(
                    content,
                    Encoding.UTF8,
                    "application/json")
            };

            return Task.FromResult(response);
        }
    }

    private static byte[] Decode(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        return Convert.FromBase64String(padded);
    }
}
