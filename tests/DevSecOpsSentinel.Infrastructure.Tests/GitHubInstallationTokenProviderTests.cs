using System.Net;
using System.Security.Cryptography;
using System.Text;
using DevSecOpsSentinel.Infrastructure.GitHub;

namespace DevSecOpsSentinel.Infrastructure.Tests;

/// <summary>
/// The installation-token exchange: a signed App JWT goes out, a short-lived
/// installation token comes back and is cached until near expiry. The cache is the
/// security-relevant part — every avoidable exchange is an avoidable place for the
/// App credential to travel.
/// </summary>
public sealed class GitHubInstallationTokenProviderTests : IDisposable
{
    private readonly string _keyDirectory =
        Directory.CreateDirectory(Path.Join(Path.GetTempPath(), Guid.NewGuid().ToString("N"))).FullName;

    private GitHubOptions Options()
    {
        string keyPath = Path.Join(_keyDirectory, "app.pem");
        using RSA rsa = RSA.Create(2048);
        File.WriteAllText(keyPath, rsa.ExportRSAPrivateKeyPem());
        return new GitHubOptions
        {
            Enabled = true,
            AppId = 1,
            InstallationId = 42,
            PrivateKeyPath = keyPath,
            AllowedRepositories = ["octo/Sandbox"],
            ApiBaseUrl = "https://api.github.test"
        };
    }

    private sealed class FakeHttp(Func<HttpRequestMessage, HttpResponseMessage> respond)
        : HttpMessageHandler, IHttpClientFactory
    {
        public List<HttpRequestMessage> Requests { get; } = [];
        public HttpClient CreateClient(string name) => new(this);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            return Task.FromResult(respond(request));
        }
    }

    private static HttpResponseMessage TokenResponse(string token, DateTimeOffset expires) =>
        new(HttpStatusCode.Created)
        {
            Content = new StringContent(
                $$"""{ "token": "{{token}}", "expires_at": "{{expires:O}}" }""",
                Encoding.UTF8,
                "application/json")
        };

    private GitHubInstallationTokenProvider Provider(GitHubOptions options, FakeHttp http) =>
        new(http, options, new GitHubAppJwtFactory(options, new GitHubPrivateKeySource(options)),
            new GitHubPrivateKeySource(options));

    [Fact]
    public async Task Exchanges_a_signed_app_jwt_for_the_installation_token()
    {
        GitHubOptions options = Options();
        FakeHttp http = new(_ => TokenResponse("inst-token", DateTimeOffset.UtcNow.AddMinutes(50)));

        string token = await Provider(options, http).GetTokenAsync(CancellationToken.None);

        Assert.Equal("inst-token", token);
        HttpRequestMessage request = Assert.Single(http.Requests);
        Assert.EndsWith("/app/installations/42/access_tokens", request.RequestUri!.AbsolutePath);
        // The outgoing credential is the App JWT, not anything cached or stored.
        Assert.Equal("Bearer", request.Headers.Authorization?.Scheme);
        Assert.Equal(2, request.Headers.Authorization!.Parameter!.Count(c => c == '.'));
    }

    [Fact]
    public async Task A_fresh_token_is_served_from_cache_without_a_second_exchange()
    {
        GitHubOptions options = Options();
        FakeHttp http = new(_ => TokenResponse("inst-token", DateTimeOffset.UtcNow.AddMinutes(50)));
        GitHubInstallationTokenProvider provider = Provider(options, http);

        await provider.GetTokenAsync(CancellationToken.None);
        string second = await provider.GetTokenAsync(CancellationToken.None);

        Assert.Equal("inst-token", second);
        Assert.Single(http.Requests);
    }

    [Fact]
    public async Task A_nearly_expired_token_is_exchanged_again()
    {
        GitHubOptions options = Options();
        int calls = 0;
        FakeHttp http = new(_ => TokenResponse($"token-{++calls}", DateTimeOffset.UtcNow.AddSeconds(5)));
        GitHubInstallationTokenProvider provider = Provider(options, http);

        await provider.GetTokenAsync(CancellationToken.None);
        string second = await provider.GetTokenAsync(CancellationToken.None);

        // Five seconds of validity is inside any sane refresh margin, so the second
        // request must not trust the cache.
        Assert.Equal("token-2", second);
        Assert.Equal(2, http.Requests.Count);
    }

    [Fact]
    public async Task Unconfigured_options_are_refused_before_any_request()
    {
        FakeHttp http = new(_ => throw new InvalidOperationException("must not be called"));
        var options = new GitHubOptions();
        var provider = new GitHubInstallationTokenProvider(
            http, options, new GitHubAppJwtFactory(options, new GitHubPrivateKeySource(options)),
            new GitHubPrivateKeySource(options));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.GetTokenAsync(CancellationToken.None));
        Assert.Empty(http.Requests);
    }

    [Fact]
    public async Task A_github_error_carries_no_token_and_says_so()
    {
        GitHubOptions options = Options();
        FakeHttp http = new(_ => new HttpResponseMessage(HttpStatusCode.Unauthorized));

        await Assert.ThrowsAsync<HttpRequestException>(
            () => Provider(options, http).GetTokenAsync(CancellationToken.None));
    }

    [Fact]
    public async Task A_success_without_a_token_in_the_body_is_rejected()
    {
        GitHubOptions options = Options();
        FakeHttp http = new(_ => new HttpResponseMessage(HttpStatusCode.Created)
        {
            Content = new StringContent("""{ "token": "" }""", Encoding.UTF8, "application/json")
        });

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => Provider(options, http).GetTokenAsync(CancellationToken.None));
    }

    public void Dispose()
    {
        // Best-effort cleanup of the per-test key directory. A failure must not fail
        // the test run, but it is never silent: the leftover path and the reason go to
        // the test output, because an empty catch discards the one piece of evidence
        // anyone debugging a full temp disk would need.
        try
        {
            Directory.Delete(_keyDirectory, recursive: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine(
                $"Test cleanup left '{_keyDirectory}' behind: {exception.Message}");
        }
    }
}
