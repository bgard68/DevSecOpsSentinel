using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Rules;

/// <summary>
/// Reports a reusable workflow call that forwards every secret.
///
/// <c>secrets: inherit</c> passes the whole secret store to the called workflow,
/// including secrets it has no use for. If that workflow lives in another
/// repository, or a later change to it adds a step that exfiltrates what it was
/// handed, the blast radius is every secret the caller can see rather than the
/// ones the job actually needs.
/// </summary>
public sealed class InheritedSecretsRule : IWorkflowSecurityRule
{
    public string RuleId => "GHA008";

    public string Title =>
        "Reusable workflow call forwards every secret";

    public WorkflowSeverity Severity => WorkflowSeverity.High;

    public IReadOnlyList<WorkflowFinding> Evaluate(ParsedWorkflow workflow) =>
        workflow.Structure.Jobs
            .Where(job =>
                job.Secrets is not null &&
                job.Secrets.Equals("inherit", StringComparison.OrdinalIgnoreCase))
            .Select(job => new WorkflowFinding(
                RuleId,
                Severity,
                Title,
                $"Job '{job.Name}' forwards the entire secret store to " +
                $"'{job.Uses ?? "the called workflow"}', not only the secrets it needs.",
                job.SecretsLine ?? job.Line,
                "Pass named secrets explicitly with a secrets: mapping, so the " +
                "called workflow receives only what it uses.",
                false))
            .ToArray();
}
