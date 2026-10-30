using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Rules;

/// <summary>
/// Merging a pull request starts two runs of the same workflow in the same second:
/// the push to the base branch — the production deploy — and the pull request's
/// <c>closed</c> event, which exists to tear down the preview environment. On the
/// closed event of a merged pull request the ref no longer separates the two, so a
/// concurrency group that ignores the event puts both runs in one group, and
/// <c>cancel-in-progress: true</c> lets the teardown cancel the deploy. The
/// teardown then finishes green and production quietly keeps serving the previous
/// build — the shape that left a frontend undeployed on every losing race for four
/// weeks before it was caught (2026-10-29). Naming <c>github.event_name</c> in the
/// group restores the intended semantics: a deploy is superseded only by a newer
/// deploy.
/// </summary>
public sealed class SelfCancellingDeployRule : IWorkflowSecurityRule
{
    public string RuleId => "GHA013";
    public string Title => "Pull request teardown can cancel the push deploy";
    public WorkflowSeverity Severity => WorkflowSeverity.Medium;

    public IReadOnlyList<WorkflowFinding> Evaluate(ParsedWorkflow workflow)
    {
        WorkflowStructure structure = workflow.Structure;
        WorkflowConcurrency? concurrency = structure.Concurrency;

        bool teardownTrigger =
            structure.TriggerDeclaresType("pull_request", "closed") ||
            structure.TriggerDeclaresType("pull_request_target", "closed");

        if (concurrency is null ||
            !teardownTrigger ||
            !structure.HasTrigger("push"))
        {
            return [];
        }

        // Raw text on purpose — the hazard is what the author wrote. An expression
        // in cancel-in-progress (such as gating on the ref) is a decision, not this
        // defect, and a group naming github.event_name keeps the two events apart.
        bool cancelsInProgress = string.Equals(
            concurrency.CancelInProgress?.Trim(),
            "true",
            StringComparison.OrdinalIgnoreCase);

        bool groupSeparatesEvents =
            concurrency.Group?.Contains(
                "github.event_name",
                StringComparison.OrdinalIgnoreCase) == true;

        if (!cancelsInProgress || groupSeparatesEvents)
        {
            return [];
        }

        return
        [
            new WorkflowFinding(
                RuleId,
                Severity,
                Title,
                "Merging a pull request runs the push deploy and the closed-event " +
                "teardown in the same concurrency group, and cancel-in-progress lets " +
                "the teardown cancel the deploy while reporting green.",
                concurrency.Line,
                "Include ${{ github.event_name }} in the concurrency group, or stop " +
                "cancelling in-progress runs for pushes.",
                false)
        ];
    }
}
