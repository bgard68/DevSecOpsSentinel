using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Rules;

/// <summary>
/// Reports the <c>pull_request_target</c> trigger, at the severity the workflow
/// actually earns.
///
/// The trigger is not a defect on its own. It exists so a workflow can label a
/// pull request, post a comment, or read a secret for a fork's PR — work that
/// <c>pull_request</c> cannot do because it has no token worth using. Those
/// workflows are the documented, recommended pattern, and reporting them as
/// Critical put a correct configuration in the band reserved for a live remote
/// execution path. A Critical that cannot be acted on is the one that teaches a
/// reader to stop looking at Criticals.
///
/// What makes it dangerous is executing the contributor's code inside that
/// privileged context, and that is a property the workflow states: whether some
/// job checks out the pull request's own head. When it does, this stays Critical
/// and GHA007 names the exact step. When it does not, the trigger is still worth
/// a reader's attention — a later edit could add the checkout — so it is
/// reported at Low as a boundary to confirm rather than damage to repair.
/// </summary>
public sealed class UnsafePullRequestTargetRule : IWorkflowSecurityRule
{
    public string RuleId => "GHA004";
    public string Title => "pull_request_target requires careful trust boundaries";

    /// <summary>The worst this rule can report; findings carry what they earn.</summary>
    public WorkflowSeverity Severity => WorkflowSeverity.Critical;

    public IReadOnlyList<WorkflowFinding> Evaluate(ParsedWorkflow workflow)
    {
        if (!workflow.Triggers.Any(trigger =>
            trigger.Contains("pull_request_target", StringComparison.Ordinal)))
        {
            return [];
        }

        WorkflowLine? triggerLine = workflow.Lines.FirstOrDefault(line =>
            line.Text.StartsWith("pull_request_target:", StringComparison.Ordinal));

        bool executesUntrustedCode = UntrustedPullRequestCheckout.PresentIn(workflow);

        return
        [
            executesUntrustedCode
                ? new WorkflowFinding(
                    RuleId,
                    WorkflowSeverity.Critical,
                    Title,
                    "This trigger runs in the base repository context with secrets and "
                        + "a writable token, and a job checks out the pull request's own "
                        + "head, so contributor-controlled code executes with them.",
                    triggerLine?.Number,
                    "Prefer pull_request, or keep pull_request_target and do not check "
                        + "out or execute pull-request code in the same job.",
                    false)
                : new WorkflowFinding(
                    RuleId,
                    WorkflowSeverity.Low,
                    Title,
                    "This trigger runs in the base repository context with secrets and "
                        + "a writable token. No job checks out the pull request's head, "
                        + "so no contributor code runs with them today - the exposure "
                        + "would come from a later edit that adds one.",
                    triggerLine?.Number,
                    "Confirm this workflow never checks out or executes pull-request "
                        + "code, and keep it to the work that needs the privileged "
                        + "context, such as labelling or commenting.",
                    false)
        ];
    }
}
