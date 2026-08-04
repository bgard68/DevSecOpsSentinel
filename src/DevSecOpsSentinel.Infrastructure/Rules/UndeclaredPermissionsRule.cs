using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Rules;

/// <summary>
/// Reports a workflow that never states what the job token may do.
///
/// With no <c>permissions</c> block at either scope, the token receives whatever
/// the repository default grants. That default is a repository setting rather
/// than a property of the workflow, so the same file is least-privileged in one
/// repository and write-scoped in another, and nothing in review shows which.
///
/// GHA002 reports permissions that are explicitly too broad. This reports the
/// absence of any statement at all, which is the case GHA002 cannot see.
/// </summary>
public sealed class UndeclaredPermissionsRule : IWorkflowSecurityRule
{
    public string RuleId => "GHA009";

    public string Title =>
        "Workflow does not declare token permissions";

    public WorkflowSeverity Severity => WorkflowSeverity.Medium;

    public IReadOnlyList<WorkflowFinding> Evaluate(ParsedWorkflow workflow)
    {
        // A workflow with no jobs at all is malformed rather than permissive,
        // and the parser reports that separately.
        if (workflow.Structure.Jobs.Count == 0 ||
            !workflow.Structure.DeclaresNoPermissions)
        {
            return [];
        }

        return
        [
            new WorkflowFinding(
                RuleId,
                Severity,
                Title,
                "Neither the workflow nor any job declares permissions, so the " +
                "job token inherits the repository default. The effective grant " +
                "is not visible in the workflow itself.",
                null,
                "Add permissions: read-all at workflow scope, then grant only the " +
                "specific write permissions individual jobs require.",
                false)
        ];
    }
}
