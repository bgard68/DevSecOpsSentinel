using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using DevSecOpsSentinel.Application;

namespace DevSecOpsSentinel.Infrastructure.GitHub;

public sealed class GitHubActionReferenceResolver(
    HttpClient httpClient,
    GitHubOptions options,
    IGitHubInstallationTokenProvider tokenProvider)
    : IWorkflowActionReferenceResolver
{
    private const int MaximumTagDereferences = 5;

    public async Task<string?> ResolveCommitShaAsync(
        string actionReference,
        CancellationToken cancellationToken)
    {
        if (!TryParseActionReference(
            actionReference,
            out string owner,
            out string repository,
            out string reference))
        {
            return null;
        }

        if (IsFullCommitSha(reference))
        {
            return reference.ToLowerInvariant();
        }

        try
        {
            GitObject? target = await ResolveReferenceAsync(
                owner,
                repository,
                reference,
                cancellationToken);

            for (int depth = 0;
                 target is not null &&
                 string.Equals(
                     target.Type,
                     "tag",
                     StringComparison.OrdinalIgnoreCase) &&
                 depth < MaximumTagDereferences;
                 depth++)
            {
                target = await ResolveAnnotatedTagAsync(
                    owner,
                    repository,
                    target.Sha,
                    cancellationToken);
            }

            return target is not null &&
                   string.Equals(
                       target.Type,
                       "commit",
                       StringComparison.OrdinalIgnoreCase) &&
                   IsFullCommitSha(target.Sha)
                ? target.Sha.ToLowerInvariant()
                : null;
        }
        catch (HttpRequestException)
        {
            return null;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    private async Task<GitObject?> ResolveReferenceAsync(
        string owner,
        string repository,
        string reference,
        CancellationToken cancellationToken)
    {
        GitReferenceResponse? tag = await GetAsync<GitReferenceResponse>(
            $"/repos/{Escape(owner)}/{Escape(repository)}/git/ref/tags/{Escape(reference)}",
            cancellationToken);

        if (tag is not null)
        {
            return tag.Object;
        }

        GitReferenceResponse? branch = await GetAsync<GitReferenceResponse>(
            $"/repos/{Escape(owner)}/{Escape(repository)}/git/ref/heads/{Escape(reference)}",
            cancellationToken);

        return branch?.Object;
    }

    private async Task<GitObject?> ResolveAnnotatedTagAsync(
        string owner,
        string repository,
        string tagSha,
        CancellationToken cancellationToken)
    {
        GitTagResponse? tag = await GetAsync<GitTagResponse>(
            $"/repos/{Escape(owner)}/{Escape(repository)}/git/tags/{Escape(tagSha)}",
            cancellationToken);

        return tag?.Object;
    }

    private async Task<T?> GetAsync<T>(
        string path,
        CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(
            HttpMethod.Get,
            $"{options.ApiBaseUrl.TrimEnd('/')}{path}");

        if (options.IsConfigured)
        {
            string token = await tokenProvider.GetTokenAsync(
                cancellationToken);

            request.Headers.Authorization =
                new AuthenticationHeaderValue("Bearer", token);
        }

        request.Headers.Accept.ParseAdd(
            "application/vnd.github+json");
        request.Headers.UserAgent.ParseAdd(
            "DevSecOpsSentinel/1.0.0");
        request.Headers.Add(
            "X-GitHub-Api-Version",
            "2022-11-28");

        using HttpResponseMessage response =
            await httpClient.SendAsync(request, cancellationToken);

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return default;
        }

        response.EnsureSuccessStatusCode();

        return await response.Content.ReadFromJsonAsync<T>(
            cancellationToken);
    }

    private static bool TryParseActionReference(
        string actionReference,
        out string owner,
        out string repository,
        out string reference)
    {
        owner = string.Empty;
        repository = string.Empty;
        reference = string.Empty;

        int atIndex = actionReference.LastIndexOf('@');
        if (atIndex <= 0 || atIndex == actionReference.Length - 1)
        {
            return false;
        }

        string actionPath = actionReference[..atIndex].Trim();
        reference = actionReference[(atIndex + 1)..].Trim();

        if (actionPath.StartsWith("./", StringComparison.Ordinal) ||
            actionPath.StartsWith(
                "docker://",
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string[] segments = actionPath.Split(
            '/',
            StringSplitOptions.RemoveEmptyEntries);

        if (segments.Length < 2)
        {
            return false;
        }

        owner = segments[0];
        repository = segments[1];

        return owner.Length > 0 &&
               repository.Length > 0 &&
               reference.Length > 0;
    }

    private static bool IsFullCommitSha(string value) =>
        value.Length == 40 &&
        value.All(character =>
            character is >= '0' and <= '9' ||
            character is >= 'a' and <= 'f' ||
            character is >= 'A' and <= 'F');

    private static string Escape(string value) =>
        Uri.EscapeDataString(value);

    private sealed record GitReferenceResponse(
        [property: JsonPropertyName("object")]
        GitObject Object);

    private sealed record GitTagResponse(
        [property: JsonPropertyName("object")]
        GitObject Object);

    private sealed record GitObject(
        [property: JsonPropertyName("type")]
        string Type,
        [property: JsonPropertyName("sha")]
        string Sha);
}
