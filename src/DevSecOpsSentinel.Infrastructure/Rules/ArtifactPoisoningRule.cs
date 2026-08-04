using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Rules;

/// <summary>
/// Reports an artifact downloaded into a privileged <c>workflow_run</c> job.
///
/// <c>workflow_run</c> runs in the base repository's context with secrets and a
/// writable token, and its usual purpose is to pick up something a
/// less-privileged pull-request workflow produced. That artifact is
/// contributor-controlled: its contents, its file names, and its paths. Treating
/// it as trusted input — unpacking it over the workspace, executing anything
/// inside it, or feeding it to a build — hands the privileged context to whoever
/// opened the pull request.
/// </summary>
public sealed class ArtifactPoisoningRule : IWorkflowSecurityRule
{
    public string RuleId => "GHA011";

    public string Title =>
        "Privileged workflow_run job consumes an untrusted artifact";

    public WorkflowSeverity Severity => WorkflowSeverity.High;

    public IReadOnlyList<WorkflowFinding> Evaluate(ParsedWorkflow workflow)
    {
        if (!workflow.Structure.HasTrigger("workflow_run"))
        {
            return [];
        }

        return workflow.Structure.AllSteps
            .Where(step => step.IsAction("actions", "download-artifact"))
            .Select(step => new WorkflowFinding(
                RuleId,
                Severity,
                Title,
                "This job runs with the base repository's secrets and downloads an " +
                "artifact produced by the triggering workflow. Artifact contents " +
                "and paths are controlled by whoever opened the pull request.",
                step.UsesLine ?? step.Line,
                "Validate the artifact before use: extract to a scratch directory, " +
                "check the paths it contains, and never execute anything from it in " +
                "the privileged job.",
                false))
            .ToArray();
    }
}
