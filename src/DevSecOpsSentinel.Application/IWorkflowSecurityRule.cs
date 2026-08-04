using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Application;

public interface IWorkflowSecurityRule
{
    string RuleId { get; }
    string Title { get; }
    WorkflowSeverity Severity { get; }
    IReadOnlyList<WorkflowFinding> Evaluate(ParsedWorkflow workflow);
}
