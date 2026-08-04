using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using DevSecOpsSentinel.Application;

namespace DevSecOpsSentinel.Infrastructure.GitHub;

public sealed class GitHubInstallationTokenProvider(
    IHttpClientFactory httpClientFactory,
    GitHubOptions options,
    GitHubAppJwtFactory jwtFactory) : IGitHubInstallationTokenProvider
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private string? _cachedToken;
    private DateTimeOffset _expiresAtUtc;

    public async Task<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        if (!options.IsConfigured)
        {
            throw new InvalidOperationException(
                "GitHub integration is not configured.");
        }

        if (!File.Exists(options.PrivateKeyPath))
        {
            throw new InvalidOperationException(
                "The configured GitHub App private key file is unavailable.");
        }

        if (CanUseCachedToken())
        {
            return _cachedToken!;
        }

        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (CanUseCachedToken())
            {
                return _cachedToken!;
            }

            using var request = new HttpRequestMessage(
                HttpMethod.Post,
                $"{options.ApiBaseUrl.TrimEnd('/')}/app/installations/{options.InstallationId}/access_tokens");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", jwtFactory.CreateToken(DateTimeOffset.UtcNow));
            request.Headers.Accept.ParseAdd("application/vnd.github+json");
            request.Headers.UserAgent.ParseAdd("DevSecOpsSentinel/0.4.0");
            request.Headers.Add("X-GitHub-Api-Version", "2022-11-28");

            HttpClient httpClient =
                httpClientFactory.CreateClient("GitHub");

            using HttpResponseMessage response =
                await httpClient.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken);
            response.EnsureSuccessStatusCode();
            InstallationTokenResponse? token = await response.Content.ReadFromJsonAsync<InstallationTokenResponse>(cancellationToken);
            if (token is null || string.IsNullOrWhiteSpace(token.Token))
            {
                throw new InvalidOperationException("GitHub did not return an installation token.");
            }

            _cachedToken = token.Token;
            _expiresAtUtc = token.ExpiresAt;
            return _cachedToken;
        }
        finally
        {
            _gate.Release();
        }
    }

    private bool CanUseCachedToken() =>
        !string.IsNullOrWhiteSpace(_cachedToken) &&
        _expiresAtUtc > DateTimeOffset.UtcNow.AddMinutes(2);

    private sealed record InstallationTokenResponse(
        [property: JsonPropertyName("token")] string Token,
        [property: JsonPropertyName("expires_at")] DateTimeOffset ExpiresAt);
}
