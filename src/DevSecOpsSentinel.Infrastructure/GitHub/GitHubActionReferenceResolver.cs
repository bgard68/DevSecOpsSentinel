using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.GitHub;

public sealed class GitHubActionReferenceResolver(
    IHttpClientFactory httpClientFactory,
    GitHubOptions options,
    IGitHubInstallationTokenProvider tokenProvider)
    : IWorkflowActionReferenceResolver
{
    private const int MaximumTagDereferences = 5;

    public async Task<ActionReferenceResolutionResult> ResolveAsync(
        string actionReference,
        CancellationToken cancellationToken)
    {
        if (!TryParseActionReference(
            actionReference,
            out string owner,
            out string repository,
            out string reference))
        {
            return new ActionReferenceResolutionResult(
                ActionReferenceResolutionStatus.Unsupported,
                null,
                $"Action reference '{actionReference}' is local, Docker-based, or malformed.");
        }

        if (IsFullCommitSha(reference))
        {
            return new ActionReferenceResolutionResult(
                ActionReferenceResolutionStatus.Resolved,
                reference.ToLowerInvariant(),
                "The action is already pinned to a full commit SHA.");
        }

        try
        {
            LookupResult<GitObject> lookup = await ResolveReferenceAsync(
                owner,
                repository,
                reference,
                cancellationToken);

            if (!lookup.IsSuccess)
            {
                return lookup.ToResolutionResult(actionReference);
            }

            GitObject? target = lookup.Value;

            for (int depth = 0;
                 target is not null &&
                 string.Equals(
                     target.Type,
                     "tag",
                     StringComparison.OrdinalIgnoreCase) &&
                 depth < MaximumTagDereferences;
                 depth++)
            {
                LookupResult<GitObject> tagLookup =
                    await ResolveAnnotatedTagAsync(
                        owner,
                        repository,
                        target.Sha,
                        cancellationToken);

                if (!tagLookup.IsSuccess)
                {
                    return tagLookup.ToResolutionResult(actionReference);
                }

                target = tagLookup.Value;
            }

            if (target is not null &&
                string.Equals(
                    target.Type,
                    "commit",
                    StringComparison.OrdinalIgnoreCase) &&
                IsFullCommitSha(target.Sha))
            {
                return new ActionReferenceResolutionResult(
                    ActionReferenceResolutionStatus.Resolved,
                    target.Sha.ToLowerInvariant(),
                    $"Resolved '{actionReference}' to a verified Git commit.");
            }

            return new ActionReferenceResolutionResult(
                ActionReferenceResolutionStatus.Failed,
                null,
                $"GitHub returned an unsupported object for '{actionReference}'.");
        }
        catch (HttpRequestException exception)
        {
            return new ActionReferenceResolutionResult(
                ActionReferenceResolutionStatus.NetworkUnavailable,
                null,
                $"GitHub could not be reached while resolving '{actionReference}': {exception.Message}");
        }
        catch (InvalidOperationException exception)
        {
            return new ActionReferenceResolutionResult(
                ActionReferenceResolutionStatus.AuthenticationFailed,
                null,
                $"GitHub authentication was unavailable while resolving '{actionReference}': {exception.Message}");
        }
    }

    private async Task<LookupResult<GitObject>> ResolveReferenceAsync(
        string owner,
        string repository,
        string reference,
        CancellationToken cancellationToken)
    {
        LookupResult<GitReferenceResponse> tag =
            await GetAsync<GitReferenceResponse>(
                $"/repos/{Escape(owner)}/{Escape(repository)}/git/ref/tags/{Escape(reference)}",
                cancellationToken);

        if (tag.IsSuccess)
        {
            return LookupResult<GitObject>.Success(tag.Value!.Object);
        }

        if (tag.Status != ActionReferenceResolutionStatus.NotFound)
        {
            return LookupResult<GitObject>.Failure(
                tag.Status,
                tag.Message);
        }

        LookupResult<GitReferenceResponse> branch =
            await GetAsync<GitReferenceResponse>(
                $"/repos/{Escape(owner)}/{Escape(repository)}/git/ref/heads/{Escape(reference)}",
                cancellationToken);

        return branch.IsSuccess
            ? LookupResult<GitObject>.Success(branch.Value!.Object)
            : LookupResult<GitObject>.Failure(
                branch.Status,
                branch.Message);
    }

    private async Task<LookupResult<GitObject>> ResolveAnnotatedTagAsync(
        string owner,
        string repository,
        string tagSha,
        CancellationToken cancellationToken)
    {
        LookupResult<GitTagResponse> tag =
            await GetAsync<GitTagResponse>(
                $"/repos/{Escape(owner)}/{Escape(repository)}/git/tags/{Escape(tagSha)}",
                cancellationToken);

        return tag.IsSuccess
            ? LookupResult<GitObject>.Success(tag.Value!.Object)
            : LookupResult<GitObject>.Failure(
                tag.Status,
                tag.Message);
    }

    private async Task<LookupResult<T>> GetAsync<T>(
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
            ProductInfo.UserAgent);
        request.Headers.Add(
            "X-GitHub-Api-Version",
            "2022-11-28");

        HttpClient httpClient =
            httpClientFactory.CreateClient("GitHub");

        using HttpResponseMessage response =
            await httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken);

        if (response.IsSuccessStatusCode)
        {
            T? value = await response.Content.ReadFromJsonAsync<T>(
                cancellationToken);

            return value is null
                ? LookupResult<T>.Failure(
                    ActionReferenceResolutionStatus.Failed,
                    "GitHub returned an empty response.")
                : LookupResult<T>.Success(value);
        }

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return LookupResult<T>.Failure(
                ActionReferenceResolutionStatus.NotFound,
                "The action tag or branch was not found.");
        }

        if (response.StatusCode == HttpStatusCode.TooManyRequests ||
            (response.StatusCode == HttpStatusCode.Forbidden &&
             response.Headers.TryGetValues(
                 "X-RateLimit-Remaining",
                 out IEnumerable<string>? remaining) &&
             remaining.Contains("0", StringComparer.Ordinal)))
        {
            return LookupResult<T>.Failure(
                ActionReferenceResolutionStatus.RateLimited,
                "GitHub rate-limited the action reference lookup.");
        }

        if (response.StatusCode is
            HttpStatusCode.Unauthorized or
            HttpStatusCode.Forbidden)
        {
            return LookupResult<T>.Failure(
                ActionReferenceResolutionStatus.AuthenticationFailed,
                "GitHub rejected the credentials used for action reference resolution.");
        }

        return LookupResult<T>.Failure(
            ActionReferenceResolutionStatus.Failed,
            $"GitHub returned HTTP {(int)response.StatusCode}.");
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

    private sealed record LookupResult<T>(
        bool IsSuccess,
        T? Value,
        ActionReferenceResolutionStatus Status,
        string Message)
    {
        public static LookupResult<T> Success(T value) =>
            new(
                true,
                value,
                ActionReferenceResolutionStatus.Resolved,
                string.Empty);

        public static LookupResult<T> Failure(
            ActionReferenceResolutionStatus status,
            string message) =>
            new(false, default, status, message);

        public ActionReferenceResolutionResult ToResolutionResult(
            string actionReference) =>
            new(
                Status,
                null,
                $"{Message} Reference: '{actionReference}'.");
    }
}
