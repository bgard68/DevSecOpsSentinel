using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Rules;

public sealed class MissingTimeoutRule : IWorkflowSecurityRule
{
    public string RuleId => "GHA003";
    public string Title => "Job does not define a timeout";
    public WorkflowSeverity Severity => WorkflowSeverity.Medium;

    // Jobs come from the document structure, so a job keyed with quotes, defined
    // through an anchor, or written in flow style is still recognised as a job,
    // and a nested mapping that merely looks like one at the same indentation is
    // not.
    public IReadOnlyList<WorkflowFinding> Evaluate(ParsedWorkflow workflow) =>
        workflow.Structure.Jobs
            .Where(job => job.TimeoutLine is null)
            .Select(job => new WorkflowFinding(
                RuleId,
                Severity,
                Title,
                $"Job '{job.Name}' can run until the platform limit is reached.",
                job.Line,
                "Add an explicit timeout-minutes value appropriate for the job.",
                true))
            .ToArray();
}
