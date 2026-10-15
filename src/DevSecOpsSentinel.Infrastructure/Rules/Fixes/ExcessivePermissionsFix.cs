using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Rules.Fixes;

/// <summary>
/// Repairs the one GHA002 finding that has a single correct answer: <c>write-all</c>, which
/// becomes <c>read-all</c>.
///
/// Every other excessive grant is left to the author. Narrowing <c>contents: write</c>
/// requires knowing which of the job's steps still needs to write, and guessing wrong
/// produces a patch that breaks the workflow — so the rule reports those and proposes
/// nothing. See <see cref="ExcessivePermissionsRule"/> for detection.
/// </summary>
public sealed class ExcessivePermissionsFix : IWorkflowFix
{
    public string RuleId => "GHA002";

    public Task<WorkflowFixResult> ProposeAsync(
        WorkflowFixContext context,
        WorkflowFinding finding,
        CancellationToken cancellationToken)
    {
        string line = context.Line(finding.LineNumber!.Value);

        // The trailing comment is removed before comparing so "permissions: write-all # why"
        // is still recognised, and preserved nowhere else because the replacement line has
        // no use for it.
        if (!RemoveTrailingComment(line.Trim())
            .Equals("permissions: write-all", StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(WorkflowFixResult.NotApplicable);
        }

        string indent = line[..(line.Length - line.TrimStart().Length)];

        return Task.FromResult(
            WorkflowFixResult.Applied(
                WorkflowLineEdit.Replace(
                    finding.LineNumber.Value,
                    indent + "permissions: read-all")));
    }

    private static string RemoveTrailingComment(string text)
    {
        int commentIndex = text.IndexOf('#');

        return commentIndex >= 0
            ? text[..commentIndex].TrimEnd()
            : text;
    }
}
