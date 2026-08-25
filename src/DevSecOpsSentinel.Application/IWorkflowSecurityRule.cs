using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Application;

public interface IWorkflowSecurityRule
{
    string RuleId { get; }
    string Title { get; }
    WorkflowSeverity Severity { get; }
    IReadOnlyList<WorkflowFinding> Evaluate(ParsedWorkflow workflow);

    /// <summary>
    /// What this rule examined and accepted rather than reported.
    ///
    /// Defaulted so a rule that never suppresses anything needs no opinion here;
    /// only the rules that establish need before reporting override it.
    /// </summary>
    IReadOnlyList<WorkflowAcknowledgement> Acknowledge(ParsedWorkflow workflow) => [];
}
