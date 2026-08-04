using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Rules;

/// <summary>
/// Reports the combination that turns <c>pull_request_target</c> into remote code
/// execution: a privileged trigger plus an explicit checkout of the pull
/// request's own head.
///
/// <c>pull_request_target</c> runs in the base repository's context with access
/// to secrets and a writable token. That is safe only while the job never
/// executes the contributor's code. Checking out <c>head.sha</c> or
/// <c>head.ref</c> and then building, testing, or installing dependencies hands
/// that context to anyone who can open a pull request.
///
/// GHA004 reports the trigger on its own as something needing review. This rule
/// reports the specific pairing that is exploitable rather than merely risky,
/// which is why it is separate and why it is Critical.
/// </summary>
public sealed class UntrustedCheckoutRule : IWorkflowSecurityRule
{
    public string RuleId => "GHA007";

    public string Title =>
        "Privileged trigger checks out untrusted pull-request code";

    public WorkflowSeverity Severity => WorkflowSeverity.Critical;

    private static readonly string[] UntrustedReferences =
    [
        "github.event.pull_request.head.sha",
        "github.event.pull_request.head.ref",
        "github.event.pull_request.merge_commit_sha",
        "github.head_ref",
        "refs/pull/"
    ];

    public IReadOnlyList<WorkflowFinding> Evaluate(ParsedWorkflow workflow)
    {
        bool privilegedTrigger = workflow.Triggers.Any(trigger =>
            trigger.Contains("pull_request_target", StringComparison.Ordinal));

        if (!privilegedTrigger)
        {
            return [];
        }

        return WorkflowStepReader.ReadUsesSteps(workflow)
            .Where(step => step.IsAction("actions", "checkout"))
            .Select(step => new
            {
                Step = step,
                Reference = step.InputValue("ref"),
                Line = step.InputLine("ref")
            })
            .Where(candidate =>
                candidate.Reference is not null &&
                IsUntrusted(candidate.Reference))
            .Select(candidate => new WorkflowFinding(
                RuleId,
                Severity,
                Title,
                "This job runs with the base repository's secrets and a writable " +
                "token, and checks out the pull request's own head. Any code the " +
                "job then executes is contributor-controlled.",
                (candidate.Line ?? candidate.Step.UsesLine).Number,
                "Use the pull_request trigger instead, or keep pull_request_target " +
                "and do not check out or execute pull-request code in the same job.",
                false))
            .ToArray();
    }

    private static bool IsUntrusted(string reference) =>
        UntrustedReferences.Any(candidate =>
            reference.Contains(candidate, StringComparison.OrdinalIgnoreCase));
}
