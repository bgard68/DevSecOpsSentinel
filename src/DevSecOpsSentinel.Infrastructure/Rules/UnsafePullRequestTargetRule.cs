using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Rules;

public sealed class UnsafePullRequestTargetRule : IWorkflowSecurityRule
{
    public string RuleId => "GHA004";
    public string Title => "pull_request_target requires careful trust boundaries";
    public WorkflowSeverity Severity => WorkflowSeverity.Critical;

    public IReadOnlyList<WorkflowFinding> Evaluate(ParsedWorkflow workflow)
    {
        if (!workflow.Triggers.Any(trigger => trigger.Contains("pull_request_target", StringComparison.Ordinal)))
        {
            return Array.Empty<WorkflowFinding>();
        }

        WorkflowLine? triggerLine = workflow.Lines.FirstOrDefault(line =>
            line.Text.StartsWith("pull_request_target:", StringComparison.Ordinal));

        return
        [
            new WorkflowFinding(
                RuleId,
                Severity,
                Title,
                "This trigger runs in the base repository context and can expose privileged tokens when untrusted pull-request code is executed.",
                triggerLine?.Number,
                "Prefer pull_request, or ensure no untrusted pull-request code is checked out or executed.",
                false)
        ];
    }
}
