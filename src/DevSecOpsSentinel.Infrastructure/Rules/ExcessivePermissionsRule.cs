using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Rules;

public sealed class ExcessivePermissionsRule : IWorkflowSecurityRule
{
    public string RuleId => "GHA002";
    public string Title => "Workflow grants excessive token permissions";
    public WorkflowSeverity Severity => WorkflowSeverity.High;

    public IReadOnlyList<WorkflowFinding> Evaluate(
        ParsedWorkflow workflow)
    {
        List<WorkflowFinding> findings = [];
        int? permissionsIndent = null;

        foreach (WorkflowLine line in workflow.Lines)
        {
            string text = RemoveTrailingComment(line.Text);

            if (text.Length == 0)
            {
                continue;
            }

            if (IsInlineWriteAll(text))
            {
                findings.Add(CreateFinding(
                    line,
                    isAutomaticallyFixable: true));

                permissionsIndent = null;
                continue;
            }

            if (text.Equals(
                "permissions:",
                StringComparison.OrdinalIgnoreCase))
            {
                permissionsIndent = line.Indent;
                continue;
            }

            if (permissionsIndent is null)
            {
                continue;
            }

            if (line.Indent <= permissionsIndent.Value)
            {
                permissionsIndent = null;
                continue;
            }

            if (IsWritePermissionEntry(text))
            {
                findings.Add(CreateFinding(
                    line,
                    isAutomaticallyFixable: false));
            }
        }

        return findings;
    }

    private WorkflowFinding CreateFinding(
        WorkflowLine line,
        bool isAutomaticallyFixable) =>
        new(
            RuleId,
            Severity,
            Title,
            "Write access increases the impact of a compromised workflow.",
            line.Number,
            "Use read-all or grant only the specific write permission required by the job.",
            isAutomaticallyFixable);

    private static bool IsInlineWriteAll(string text) =>
        text.Equals(
            "permissions: write-all",
            StringComparison.OrdinalIgnoreCase);

    private static bool IsWritePermissionEntry(string text)
    {
        int colonIndex = text.IndexOf(':');
        if (colonIndex <= 0)
        {
            return false;
        }

        string permissionName = text[..colonIndex].Trim();
        string permissionValue = text[(colonIndex + 1)..].Trim();

        return permissionName.Length > 0 &&
            permissionValue.Equals(
                "write",
                StringComparison.OrdinalIgnoreCase);
    }

    private static string RemoveTrailingComment(string text)
    {
        int commentIndex = text.IndexOf('#');

        return commentIndex >= 0
            ? text[..commentIndex].TrimEnd()
            : text;
    }
}
