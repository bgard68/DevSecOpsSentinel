using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Rules;

/// <summary>
/// Which write scopes a published action cannot do its job without.
///
/// A permissions rule that reports every write grant reports the correct
/// remediation as a defect. <c>github/codeql-action/analyze</c> uploads its
/// results through the code-scanning API, which requires
/// <c>security-events: write</c>; a workflow that grants it has already applied
/// "grant only the specific write permission required by the job", and telling
/// its author to remove it asks them to break code scanning to satisfy a
/// scanner. Three such grants in this repository's own workflows were carrying
/// hand-written exemptions in the test suite for exactly this reason.
///
/// What an action requires is documented, static and public, so it is a lookup
/// rather than an inference — which keeps the rule deterministic. The table is
/// deliberately conservative: an entry that is absent costs a false positive,
/// while an entry that is wrong silently suppresses a real one, so only
/// requirements that hold for every use of the action are listed, and anything
/// conditional carries the condition with it.
///
/// <c>id-token: write</c> is absent by design. It is exempted outright by
/// <see cref="ExcessivePermissionsRule"/> because it grants no repository
/// access at all, so it needs no per-action justification; it appears below
/// only where an action needs it alongside a scope that does.
/// </summary>
internal static class ActionPermissionRequirements
{
    /// <summary>
    /// One action and the scopes it needs. <see cref="AppliesTo"/> is null when
    /// the requirement is unconditional, and otherwise decides from the step's
    /// inputs — a requirement that only holds for some configurations must not
    /// excuse the grant for all of them.
    /// </summary>
    private sealed record Requirement(
        string Action,
        string[] Scopes,
        Func<WorkflowStructuredStep, bool>? AppliesTo = null);

    private static readonly Requirement[] Catalogue =
    [
        // Code scanning. Covers init, analyze and upload-sarif alike: the
        // requirement belongs to the repository, not to one entry point.
        new("github/codeql-action", ["security-events"]),

        // Only when the action is asked to post its summary as a review
        // comment. Left at its default, or set to never, it writes nothing.
        new("actions/dependency-review-action", ["pull-requests"],
            step => WantsPullRequestComment(step)),

        // Pages deployment claims the environment and exchanges an OIDC token.
        new("actions/deploy-pages", ["pages", "id-token"]),
        new("JamesIves/github-pages-deploy-action", ["contents"]),

        // Provenance is written to the attestations store.
        new("actions/attest-build-provenance", ["attestations", "id-token"]),
        new("actions/attest", ["attestations", "id-token"]),

        // Releases and tags are repository contents.
        new("softprops/action-gh-release", ["contents"]),
        new("ncipollo/release-action", ["contents"]),
        new("actions/create-release", ["contents"]),
        new("release-drafter/release-drafter", ["contents", "pull-requests"]),
        new("googleapis/release-please-action", ["contents", "pull-requests"]),
        new("google-github-actions/release-please-action", ["contents", "pull-requests"]),

        // Opening or updating a pull request writes a branch and the PR itself.
        new("peter-evans/create-pull-request", ["contents", "pull-requests"]),
        new("peter-evans/create-or-update-comment", ["issues", "pull-requests"]),
        new("peter-evans/close-pull-request", ["pull-requests"]),

        // Triage automation edits the issues and pull requests it sorts.
        new("actions/stale", ["issues", "pull-requests"]),
        new("actions/labeler", ["pull-requests"]),
        new("dessant/lock-threads", ["issues", "pull-requests"]),
        new("dependabot/fetch-metadata", ["pull-requests"]),

        // Publishing an image to GitHub Packages.
        new("docker/build-push-action", ["packages"]),

        // Dependency graph submission writes the graph for the repository.
        new("gradle/actions/dependency-submission", ["contents"]),
        new("advanced-security/maven-dependency-submission-action", ["contents"]),

        // Cloud federation: the OIDC exchange that replaces a stored secret.
        new("aws-actions/configure-aws-credentials", ["id-token"]),
        new("azure/login", ["id-token"]),
        new("google-github-actions/auth", ["id-token"])
    ];

    /// <summary>
    /// True when some step in the job runs an action that cannot work without
    /// this scope, which makes the grant the documented minimum rather than an
    /// excess.
    /// </summary>
    internal static bool IsRequiredByAnyStep(
        IEnumerable<WorkflowStructuredStep> steps,
        string scope) =>
        steps.Any(step => RequiredScopes(step)
            .Any(required => required.Equals(scope, StringComparison.OrdinalIgnoreCase)));

    /// <summary>The scopes this step's action requires, empty for an unlisted one.</summary>
    private static IEnumerable<string> RequiredScopes(WorkflowStructuredStep step)
    {
        if (step.Uses is null)
        {
            return [];
        }

        string action = WithoutReference(step.Uses);

        return Catalogue
            .Where(requirement =>
                Matches(action, requirement.Action) &&
                (requirement.AppliesTo is null || requirement.AppliesTo(step)))
            .SelectMany(requirement => requirement.Scopes);
    }

    /// <summary>
    /// Drops the <c>@ref</c>, so a SHA-pinned step matches the same entry as a
    /// tagged one. Local (<c>./path</c>) and container (<c>docker://</c>) steps
    /// carry no owner/repository and match nothing.
    /// </summary>
    private static string WithoutReference(string uses)
    {
        int at = uses.IndexOf('@');
        return at < 0 ? uses.Trim() : uses[..at].Trim();
    }

    /// <summary>
    /// Matches the action itself or any sub-action beneath it, so one entry for
    /// <c>github/codeql-action</c> covers <c>/init</c>, <c>/analyze</c> and
    /// <c>/upload-sarif</c>. The trailing separator is required: it stops
    /// <c>actions/stale</c> from matching an unrelated <c>actions/stale-x</c>.
    /// </summary>
    private static bool Matches(string action, string catalogued) =>
        action.Equals(catalogued, StringComparison.OrdinalIgnoreCase) ||
        action.StartsWith(catalogued + "/", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Whether dependency review is configured to comment on the pull request.
    ///
    /// The input is tri-state — <c>always</c>, <c>on-failure</c>, <c>never</c> —
    /// and only <c>never</c> writes nothing. Absent means the action does not
    /// comment, so the grant is not required.
    /// </summary>
    private static bool WantsPullRequestComment(WorkflowStructuredStep step) =>
        step.Input("comment-summary-in-pr") is { } value &&
        !value.Value.Trim().Equals("never", StringComparison.OrdinalIgnoreCase);
}
