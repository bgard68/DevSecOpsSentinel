using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Rules;

/// <summary>
/// The only rule here that is not a confidentiality or authorisation finding.
///
/// A job without a timeout runs until the platform limit, consuming minutes and
/// — on a self-hosted runner — occupying it. That is worth fixing, and it is not
/// the same kind of problem as a token left readable on the runner (GHA006) or a
/// grant nobody can see (GHA009), which is where it previously sat.
///
/// Reporting it alongside those flattened the distinction between "this wastes
/// resources" and "this exposes something", which is the distinction a severity
/// is for.
/// </summary>
public sealed class MissingTimeoutRule : IWorkflowSecurityRule
{
    public string RuleId => "GHA003";
    public string Title => "Job does not define a timeout";
    public WorkflowSeverity Severity => WorkflowSeverity.Low;

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
