using Microsoft.Extensions.Options;

namespace DevSecOpsSentinel.Infrastructure.GitHub;

/// <summary>
/// Rejects a GitHub configuration that cannot work, at startup.
///
/// The line this draws is between a setting that is wrong and a setting that is incomplete.
///
/// Incomplete is a supported state: the integration can be enabled before its App id,
/// installation id, key or allowlist are supplied, and the readiness probe reports that as
/// a degradation rather than refusing to serve. Deterministic analysis does not need GitHub,
/// so taking the whole application down for it would be the wrong trade — and
/// <see cref="GitHubOptions.IsConfigured"/> already expresses completeness for the code that
/// needs to ask.
///
/// Wrong is not a supported state. A negative identifier, an API base address that is not an
/// absolute HTTP URL, or an allowlist entry that is not <c>owner/repository</c> cannot become
/// correct at runtime, and the last of those fails in the direction that matters: an entry
/// that never matches reads as an allowlisted repository in the configuration file while
/// silently allowing nothing.
/// </summary>
public sealed class GitHubOptionsValidator : IValidateOptions<GitHubOptions>
{
    public ValidateOptionsResult Validate(string? name, GitHubOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        List<string> failures = [];

        if (options.AppId < 0)
        {
            failures.Add(
                $"{GitHubOptions.SectionName}:AppId cannot be negative, but was {options.AppId}.");
        }

        if (options.InstallationId < 0)
        {
            failures.Add(
                $"{GitHubOptions.SectionName}:InstallationId cannot be negative, but was "
                + $"{options.InstallationId}.");
        }

        if (!IsAbsoluteHttpUrl(options.ApiBaseUrl))
        {
            failures.Add(
                $"{GitHubOptions.SectionName}:ApiBaseUrl must be an absolute http or https "
                + $"URL, but was '{options.ApiBaseUrl}'.");
        }

        // Blank entries are ignored rather than rejected: a configuration provider can
        // materialise an empty slot for a key that was removed, and an absent entry allows
        // nothing, which is already the safe direction.
        foreach (string entry in options.AllowedRepositories
            .Where(entry => !string.IsNullOrWhiteSpace(entry))
            .Where(entry => !IsOwnerAndRepository(entry)))
        {
            failures.Add(
                $"{GitHubOptions.SectionName}:AllowedRepositories entry '{entry}' must be in "
                + "owner/repository form. An entry that cannot match allows nothing while "
                + "appearing to allow something.");
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }

    private static bool IsAbsoluteHttpUrl(string value) =>
        Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) &&
        (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp);

    private static bool IsOwnerAndRepository(string entry)
    {
        string[] segments = entry.Split('/');

        return segments.Length == 2 &&
            segments.All(segment => !string.IsNullOrWhiteSpace(segment));
    }
}
