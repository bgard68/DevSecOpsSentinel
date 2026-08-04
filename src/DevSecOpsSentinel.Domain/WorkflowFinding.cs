namespace DevSecOpsSentinel.Domain;

public sealed record WorkflowFinding(
    string RuleId,
    WorkflowSeverity Severity,
    string Title,
    string Description,
    int? LineNumber,
    string Recommendation,
    bool IsAutomaticallyFixable);
