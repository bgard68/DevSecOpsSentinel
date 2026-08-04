using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Serialization;
using DevSecOpsSentinel.Application;

namespace DevSecOpsSentinel.Infrastructure.GitHub;

public sealed class GitHubRepositoryReader(
    HttpClient httpClient,
    GitHubOptions options,
    IGitHubInstallationTokenProvider tokenProvider) : IGitHubRepositoryReader
{
    public async Task<IReadOnlyList<GitHubRepositorySummary>> GetRepositoriesAsync(CancellationToken cancellationToken)
    {
        EnsureConfigured();
        using HttpResponseMessage response = await SendAsync("/installation/repositories?per_page=100", cancellationToken);
        response.EnsureSuccessStatusCode();
        RepositoryListResponse? payload = await response.Content.ReadFromJsonAsync<RepositoryListResponse>(cancellationToken);

        return (payload?.Repositories ?? [])
            .Where(repository => options.IsAllowed(repository.Owner.Login, repository.Name))
            .Select(repository => new GitHubRepositorySummary(
                repository.Owner.Login,
                repository.Name,
                repository.FullName,
                repository.DefaultBranch,
                repository.Private,
                repository.HtmlUrl))
            .OrderBy(repository => repository.FullName, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public async Task<IReadOnlyList<GitHubWorkflowSummary>> GetWorkflowsAsync(
        string owner,
        string repository,
        CancellationToken cancellationToken)
    {
        EnsureAllowed(owner, repository);
        string path = $"/repos/{Uri.EscapeDataString(owner)}/{Uri.EscapeDataString(repository)}/contents/.github/workflows";
        using HttpResponseMessage response = await SendAsync(path, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return [];
        }

        response.EnsureSuccessStatusCode();
        ContentItem[]? items = await response.Content.ReadFromJsonAsync<ContentItem[]>(cancellationToken);
        return (items ?? [])
            .Where(item => string.Equals(item.Type, "file", StringComparison.OrdinalIgnoreCase))
            .Where(item => item.Name.EndsWith(".yml", StringComparison.OrdinalIgnoreCase) ||
                           item.Name.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase))
            .Select(item => new GitHubWorkflowSummary(item.Name, item.Path, item.Sha, item.HtmlUrl))
            .OrderBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public async Task<GitHubWorkflowFile?> GetWorkflowAsync(
        string owner,
        string repository,
        string path,
        string? reference,
        CancellationToken cancellationToken)
    {
        EnsureAllowed(owner, repository);
        string requestPath = $"/repos/{Uri.EscapeDataString(owner)}/{Uri.EscapeDataString(repository)}/contents/{EscapePath(path)}";
        if (!string.IsNullOrWhiteSpace(reference))
        {
            requestPath += $"?ref={Uri.EscapeDataString(reference)}";
        }

        using HttpResponseMessage response = await SendAsync(requestPath, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        response.EnsureSuccessStatusCode();
        ContentItem? item = await response.Content.ReadFromJsonAsync<ContentItem>(cancellationToken);
        if (item is null || string.IsNullOrWhiteSpace(item.Content) ||
            !string.Equals(item.Encoding, "base64", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("GitHub returned unsupported workflow content.");
        }

        string content = Encoding.UTF8.GetString(Convert.FromBase64String(item.Content.Replace("\n", string.Empty)));
        return new GitHubWorkflowFile(
            owner,
            repository,
            reference ?? "main",
            item.Path,
            item.Sha,
            content,
            item.HtmlUrl,
            DateTimeOffset.UtcNow);
    }

    private async Task<HttpResponseMessage> SendAsync(string path, CancellationToken cancellationToken)
    {
        string token = await tokenProvider.GetTokenAsync(cancellationToken);
        var request = new HttpRequestMessage(HttpMethod.Get, $"{options.ApiBaseUrl.TrimEnd('/')}{path}");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Accept.ParseAdd("application/vnd.github+json");
        request.Headers.UserAgent.ParseAdd("DevSecOpsSentinel/0.4.0");
        request.Headers.Add("X-GitHub-Api-Version", "2022-11-28");
        return await httpClient.SendAsync(request, cancellationToken);
    }

    private void EnsureConfigured()
    {
        if (!options.IsConfigured)
        {
            throw new InvalidOperationException("GitHub integration is not configured.");
        }
    }

    private void EnsureAllowed(string owner, string repository)
    {
        EnsureConfigured();
        if (!options.IsAllowed(owner, repository))
        {
            throw new UnauthorizedAccessException("Repository is not allowlisted.");
        }
    }

    private static string EscapePath(string path) =>
        string.Join('/', path.Split('/', StringSplitOptions.RemoveEmptyEntries).Select(Uri.EscapeDataString));

    private sealed record RepositoryListResponse(
        [property: JsonPropertyName("repositories")] RepositoryItem[] Repositories);

    private sealed record RepositoryItem(
        [property: JsonPropertyName("name")] string Name,
        [property: JsonPropertyName("full_name")] string FullName,
        [property: JsonPropertyName("default_branch")] string DefaultBranch,
        [property: JsonPropertyName("private")] bool Private,
        [property: JsonPropertyName("html_url")] string HtmlUrl,
        [property: JsonPropertyName("owner")] RepositoryOwner Owner);

    private sealed record RepositoryOwner([property: JsonPropertyName("login")] string Login);

    private sealed record ContentItem(
        [property: JsonPropertyName("name")] string Name,
        [property: JsonPropertyName("path")] string Path,
        [property: JsonPropertyName("sha")] string Sha,
        [property: JsonPropertyName("type")] string Type,
        [property: JsonPropertyName("html_url")] string HtmlUrl,
        [property: JsonPropertyName("encoding")] string? Encoding,
        [property: JsonPropertyName("content")] string? Content);
}
