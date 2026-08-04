using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Rules;

/// <summary>
/// Reports write access granted to the job token, at workflow or job scope.
///
/// Permission grants are read from the document structure rather than matched
/// textually, so flow style, values followed by comments and anchored blocks all
/// resolve the way GitHub resolves them, and a <c>write</c> value under an
/// unrelated key such as <c>with:</c> is not mistaken for a permission.
/// </summary>
public sealed class ExcessivePermissionsRule : IWorkflowSecurityRule
{
    public string RuleId => "GHA002";
    public string Title => "Workflow grants excessive token permissions";
    public WorkflowSeverity Severity => WorkflowSeverity.High;

    public IReadOnlyList<WorkflowFinding> Evaluate(ParsedWorkflow workflow) =>
        workflow.Structure.AllPermissions
            .Where(IsExcessive)
            .Select(entry => new WorkflowFinding(
                RuleId,
                Severity,
                Title,
                "Write access increases the impact of a compromised workflow.",
                entry.Line,
                "Use read-all or grant only the specific write permission required by the job.",
                IsWriteAll(entry)))
            .ToArray();

    private static bool IsExcessive(WorkflowPermissionEntry entry) =>
        IsWriteAll(entry) ||
        (entry.Name.Length > 0 &&
         entry.Value.Equals("write", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// The scalar form <c>permissions: write-all</c>, which the patch generator
    /// can rewrite to <c>read-all</c> in place. Individual grants are left to a
    /// human, because which ones a job genuinely needs is not inferable.
    /// </summary>
    private static bool IsWriteAll(WorkflowPermissionEntry entry) =>
        entry.Name.Length == 0 &&
        entry.Value.Equals("write-all", StringComparison.OrdinalIgnoreCase);
}
