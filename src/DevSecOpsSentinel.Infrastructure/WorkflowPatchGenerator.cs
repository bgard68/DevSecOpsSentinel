using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure;

public sealed class WorkflowPatchGenerator(
    IWorkflowParser parser) : IWorkflowPatchGenerator
{
    private const string PlaceholderSha =
        "0000000000000000000000000000000000000000";

    public WorkflowPatch Generate(
        ParsedWorkflow workflow,
        IReadOnlyList<WorkflowFinding> findings)
    {
        List<string> lines = workflow.Document.Content
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n')
            .Split('\n')
            .ToList();

        HashSet<int> semanticLineNumbers = workflow.Lines
            .Select(line => line.Number)
            .ToHashSet();

        HashSet<string> appliedRules = [];

        foreach (WorkflowFinding finding in findings
            .Where(finding =>
                finding.IsAutomaticallyFixable &&
                finding.RuleId != "GHA003"))
        {
            if (!CanPatchLine(
                finding.LineNumber,
                lines.Count,
                semanticLineNumbers))
            {
                continue;
            }

            int index = finding.LineNumber!.Value - 1;

            if (finding.RuleId == "GHA001")
            {
                int atIndex = lines[index].IndexOf('@');
                if (atIndex < 0)
                {
                    continue;
                }

                int commentIndex =
                    lines[index].IndexOf('#', atIndex);

                string comment = commentIndex >= 0
                    ? " " + lines[index][commentIndex..].TrimStart()
                    : string.Empty;

                string prefix = lines[index][..(atIndex + 1)];
                lines[index] = prefix + PlaceholderSha + comment;
                appliedRules.Add(finding.RuleId);
            }
            else if (
                finding.RuleId == "GHA002" &&
                lines[index].Trim().Equals(
                    "permissions: write-all",
                    StringComparison.OrdinalIgnoreCase))
            {
                string indent = lines[index][..
                    (lines[index].Length -
                     lines[index].TrimStart().Length)];

                lines[index] = indent + "permissions: read-all";
                appliedRules.Add(finding.RuleId);
            }
        }

        foreach (WorkflowFinding finding in findings
            .Where(finding =>
                finding.IsAutomaticallyFixable &&
                finding.RuleId == "GHA003")
            .OrderByDescending(finding => finding.LineNumber))
        {
            if (!CanPatchLine(
                finding.LineNumber,
                lines.Count,
                semanticLineNumbers))
            {
                continue;
            }

            int index = finding.LineNumber!.Value - 1;
            string declaration = lines[index];

            int indentCount =
                declaration.Length -
                declaration.TrimStart().Length;

            lines.Insert(
                index + 1,
                new string(' ', indentCount + 2) +
                "timeout-minutes: 15");

            appliedRules.Add(finding.RuleId);
        }

        string proposed = string.Join('\n', lines);

        bool isValid = parser
            .Parse(new WorkflowDocument(
                workflow.Document.FileName,
                proposed))
            .IsValid;

        return new WorkflowPatch(
            workflow.Document.Content,
            proposed,
            appliedRules
                .OrderBy(id => id, StringComparer.Ordinal)
                .ToArray(),
            isValid);
    }

    private static bool CanPatchLine(
        int? lineNumber,
        int lineCount,
        IReadOnlySet<int> semanticLineNumbers)
    {
        return lineNumber is >= 1 &&
            lineNumber <= lineCount &&
            semanticLineNumbers.Contains(lineNumber.Value);
    }
}
