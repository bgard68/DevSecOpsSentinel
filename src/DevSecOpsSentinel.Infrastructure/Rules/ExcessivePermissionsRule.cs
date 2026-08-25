using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Rules;

/// <summary>
/// Reports write access granted to the job token that the job does not need.
///
/// Permission grants are read from the document structure rather than matched
/// textually, so flow style, values followed by comments and anchored blocks all
/// resolve the way GitHub resolves them, and a <c>write</c> value under an
/// unrelated key such as <c>with:</c> is not mistaken for a permission.
///
/// "Excessive" is a claim about need, so the rule establishes need before making
/// it. A job-scoped grant that an action in that same job cannot work without is
/// the documented minimum, and reporting it tells the author to break their
/// workflow to satisfy the scanner — advice the rule's own remediation already
/// says not to give. <see cref="ActionPermissionRequirements"/> holds what each
/// action requires.
///
/// Severity follows what the scope can do once a workflow is compromised, rather
/// than being constant across every grant. <c>contents: write</c> can push code
/// and rewrite history; <c>security-events: write</c> can hide code-scanning
/// alerts. Both were High, which flattens a real difference and teaches readers
/// to skim the band that matters.
/// </summary>
public sealed class ExcessivePermissionsRule : IWorkflowSecurityRule
{
    public string RuleId => "GHA002";
    public string Title => "Workflow grants excessive token permissions";

    /// <summary>
    /// The worst this rule can report. Individual findings carry the severity of
    /// the scope they concern; this is the level the catalogue advertises.
    /// </summary>
    public WorkflowSeverity Severity => WorkflowSeverity.High;

    public IReadOnlyList<WorkflowFinding> Evaluate(ParsedWorkflow workflow)
    {
        List<WorkflowFinding> findings = [];

        // Workflow scope first, matching the order the structure exposes, so a
        // reader's line numbers still run down the file.
        foreach (WorkflowPermissionEntry entry in workflow.Structure.Permissions)
        {
            AddWorkflowScoped(findings, entry, workflow);
        }

        foreach (WorkflowStructuredJob job in workflow.Structure.Jobs)
        {
            foreach (WorkflowPermissionEntry entry in job.Permissions)
            {
                AddJobScoped(findings, entry, job);
            }
        }

        return findings;
    }

    /// <summary>
    /// A workflow-scoped grant reaches every job, including ones added later
    /// that have no use for it, so it is reported even when some job does need
    /// it — with the remediation changed from "remove" to "move", which is the
    /// action that actually applies.
    /// </summary>
    private void AddWorkflowScoped(
        List<WorkflowFinding> findings,
        WorkflowPermissionEntry entry,
        ParsedWorkflow workflow)
    {
        if (IsWriteAll(entry))
        {
            findings.Add(WriteAllFinding(entry));
            return;
        }

        if (!IsNamedWrite(entry))
        {
            return;
        }

        bool neededSomewhere = workflow.Structure.Jobs.Any(job =>
            ActionPermissionRequirements.IsRequiredByAnyStep(job.Steps, entry.Name));

        findings.Add(neededSomewhere
            ? new WorkflowFinding(
                RuleId,
                WorkflowSeverity.Low,
                Title,
                $"{entry.Name}: write is required by one job but granted to all of them.",
                entry.Line,
                $"Move {entry.Name}: write onto the job that needs it, leaving the "
                    + "workflow default read-only.",
                false)
            : ExcessiveFinding(entry, "workflow"));
    }

    /// <summary>
    /// A job-scoped grant an action in that job requires is already minimal, and
    /// is not reported at all.
    /// </summary>
    private void AddJobScoped(
        List<WorkflowFinding> findings,
        WorkflowPermissionEntry entry,
        WorkflowStructuredJob job)
    {
        if (IsWriteAll(entry))
        {
            findings.Add(WriteAllFinding(entry));
            return;
        }

        if (!IsNamedWrite(entry))
        {
            return;
        }

        if (ActionPermissionRequirements.IsRequiredByAnyStep(job.Steps, entry.Name))
        {
            return;
        }

        findings.Add(ExcessiveFinding(entry, "job"));
    }

    private WorkflowFinding ExcessiveFinding(WorkflowPermissionEntry entry, string scope) =>
        new(RuleId,
            SeverityFor(entry.Name),
            Title,
            $"Nothing in this {scope} needs {entry.Name}: write, and write access "
                + "increases the impact of a compromised workflow.",
            entry.Line,
            $"Drop {entry.Name}: write, or state which step requires it.",
            false);

    private WorkflowFinding WriteAllFinding(WorkflowPermissionEntry entry) =>
        new(RuleId,
            WorkflowSeverity.High,
            Title,
            "write-all grants every scope at once, including the ones that can "
                + "push code and publish packages.",
            entry.Line,
            "Use read-all or grant only the specific write permission required by the job.",
            true);

    /// <summary>
    /// What the scope can do to the repository if the job token is stolen.
    ///
    /// High is code and artefacts an attacker can make others run; Medium is
    /// project metadata they can forge; Low is signal they can suppress but not
    /// act through. An unrecognised scope is treated as Medium rather than
    /// dismissed, so a scope GitHub adds later is still reported.
    /// </summary>
    private static WorkflowSeverity SeverityFor(string name) => name.ToLowerInvariant() switch
    {
        "contents" or "packages" or "actions" or "attestations" => WorkflowSeverity.High,
        "security-events" or "checks" or "statuses" => WorkflowSeverity.Low,
        _ => WorkflowSeverity.Medium
    };

    private static bool IsNamedWrite(WorkflowPermissionEntry entry) =>
        entry.Name.Length > 0 &&
        entry.Value.Equals("write", StringComparison.OrdinalIgnoreCase) &&
        !IsIdToken(entry);

    /// <summary>
    /// <c>id-token: write</c> is not access to the repository.
    ///
    /// It permits requesting an OIDC token and nothing else; what that token can
    /// reach is decided by the trust policy on the cloud role, not by this
    /// grant. It is also the permission that REPLACES a stored deployment
    /// credential, so reporting it pushes a reader away from the safer design.
    ///
    /// The remediation this rule offers settles it: there is no useful
    /// <c>id-token: read</c>, and <c>read-all</c> does not include it. Advice
    /// that cannot be followed without breaking the workflow is not advice.
    /// </summary>
    private static bool IsIdToken(WorkflowPermissionEntry entry) =>
        entry.Name.Equals("id-token", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The scalar form <c>permissions: write-all</c>, which the patch generator
    /// can rewrite to <c>read-all</c> in place. Individual grants are left to a
    /// human, because which ones a job genuinely needs is not inferable.
    /// </summary>
    private static bool IsWriteAll(WorkflowPermissionEntry entry) =>
        entry.Name.Length == 0 &&
        entry.Value.Equals("write-all", StringComparison.OrdinalIgnoreCase);
}
