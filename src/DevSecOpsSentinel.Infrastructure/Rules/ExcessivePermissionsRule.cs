using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Rules;

public sealed class ExcessivePermissionsRule : IWorkflowSecurityRule
{
    public string RuleId => "GHA002";
    public string Title => "Workflow grants excessive token permissions";
    public WorkflowSeverity Severity => WorkflowSeverity.High;

    public IReadOnlyList<WorkflowFinding> Evaluate(ParsedWorkflow workflow) => workflow.Lines
        .Where(line => line.Text.Equals("permissions: write-all", StringComparison.OrdinalIgnoreCase) ||
            line.Text.EndsWith(": write", StringComparison.OrdinalIgnoreCase))
        .Select(line => new WorkflowFinding(
            RuleId,
            Severity,
            Title,
            "Write access increases the impact of a compromised workflow.",
            line.Number,
            "Use read-all or grant only the specific write permission required by the job.",
            line.Text.Equals("permissions: write-all", StringComparison.OrdinalIgnoreCase)))
        .ToArray();
}
