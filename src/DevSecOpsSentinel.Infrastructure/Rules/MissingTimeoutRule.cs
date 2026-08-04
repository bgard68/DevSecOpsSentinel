using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Rules;

public sealed class MissingTimeoutRule : IWorkflowSecurityRule
{
    public string RuleId => "GHA003";
    public string Title => "Job does not define a timeout";
    public WorkflowSeverity Severity => WorkflowSeverity.Medium;

    public IReadOnlyList<WorkflowFinding> Evaluate(ParsedWorkflow workflow) => workflow.Jobs
        .Where(job => job.TimeoutLine is null)
        .Select(job => new WorkflowFinding(
            RuleId,
            Severity,
            Title,
            $"Job '{job.Name}' can run until the platform limit is reached.",
            job.DeclarationLine,
            "Add an explicit timeout-minutes value appropriate for the job.",
            true))
        .ToArray();
}
