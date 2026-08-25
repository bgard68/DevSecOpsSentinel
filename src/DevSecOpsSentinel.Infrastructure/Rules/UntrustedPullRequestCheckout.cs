using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Rules;

/// <summary>
/// Whether a workflow checks out the pull request's own head — the single fact
/// that separates a privileged trigger being used safely from it being an
/// execution path for anyone who can open a pull request.
///
/// Two rules need this answer and must not drift apart on it. GHA007 reports the
/// checkout itself; GHA004 uses it to decide whether the trigger it found is a
/// live exposure or a trust boundary to confirm. Keeping one definition here
/// means a reference added to the list is honoured by both at once.
/// </summary>
internal static class UntrustedPullRequestCheckout
{
    /// <summary>
    /// References that resolve to contributor-controlled code. Substring matches,
    /// so an expression that merely embeds one of them still counts.
    /// </summary>
    internal static readonly string[] References =
    [
        "github.event.pull_request.head.sha",
        "github.event.pull_request.head.ref",
        "github.event.pull_request.merge_commit_sha",
        "github.head_ref",
        "refs/pull/"
    ];

    internal static bool IsUntrusted(string reference) =>
        References.Any(candidate =>
            reference.Contains(candidate, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// True when some checkout step in the workflow names an untrusted reference.
    ///
    /// A checkout with no <c>ref</c> takes the base branch, which is trusted, so
    /// its absence is not treated as untrusted.
    /// </summary>
    internal static bool PresentIn(ParsedWorkflow workflow) =>
        workflow.Structure.AllSteps
            .Where(step => step.IsAction("actions", "checkout"))
            .Select(step => step.Input("ref"))
            .Any(reference => reference is not null && IsUntrusted(reference.Value));
}
