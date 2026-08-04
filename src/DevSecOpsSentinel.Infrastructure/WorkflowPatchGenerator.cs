using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure;

public sealed class WorkflowPatchGenerator(
    IWorkflowParser parser,
    IEnumerable<IWorkflowSecurityRule> rules) : IWorkflowPatchGenerator
{
    private const string PlaceholderSha =
        "0000000000000000000000000000000000000000";

    private readonly IReadOnlyList<IWorkflowSecurityRule> _rules =
        rules.ToArray();

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

        List<WorkflowFinding> appliedFindings = [];

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
                appliedFindings.Add(finding);
            }
            else if (
                finding.RuleId == "GHA002" &&
                RemoveTrailingComment(lines[index].Trim()).Equals(
                    "permissions: write-all",
                    StringComparison.OrdinalIgnoreCase))
            {
                string indent = lines[index][..
                    (lines[index].Length -
                     lines[index].TrimStart().Length)];

                lines[index] = indent + "permissions: read-all";
                appliedFindings.Add(finding);
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

            appliedFindings.Add(finding);
        }

        string proposed = string.Join('\n', lines);
        WorkflowDocument proposedDocument = new(
            workflow.Document.FileName,
            proposed);

        bool proposedContentIsValid = ValidateProposedContent(
            workflow,
            findings,
            appliedFindings,
            proposedDocument);

        return new WorkflowPatch(
            workflow.Document.Content,
            proposed,
            appliedFindings
                .Select(finding => finding.RuleId)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(id => id, StringComparer.Ordinal)
                .ToArray(),
            proposedContentIsValid);
    }

    private bool ValidateProposedContent(
        ParsedWorkflow originalWorkflow,
        IReadOnlyList<WorkflowFinding> originalFindings,
        IReadOnlyList<WorkflowFinding> appliedFindings,
        WorkflowDocument proposedDocument)
    {
        WorkflowParseResult parseResult = parser.Parse(proposedDocument);

        if (!parseResult.IsValid ||
            parseResult.Workflow is not ParsedWorkflow proposedWorkflow)
        {
            return false;
        }

        if (!HasEquivalentStructure(
            originalWorkflow,
            proposedWorkflow))
        {
            return false;
        }

        WorkflowFinding[] proposedFindings = _rules
            .SelectMany(rule => rule.Evaluate(proposedWorkflow))
            .ToArray();

        IReadOnlyDictionary<string, int> originalCounts =
            CountByRule(originalFindings);

        IReadOnlyDictionary<string, int> appliedCounts =
            CountByRule(appliedFindings);

        IReadOnlyDictionary<string, int> proposedCounts =
            CountByRule(proposedFindings);

        HashSet<string> allRuleIds = originalCounts.Keys
            .Concat(proposedCounts.Keys)
            .ToHashSet(StringComparer.Ordinal);

        foreach (string ruleId in allRuleIds)
        {
            int originalCount = originalCounts.GetValueOrDefault(ruleId);
            int appliedCount = appliedCounts.GetValueOrDefault(ruleId);
            int proposedCount = proposedCounts.GetValueOrDefault(ruleId);
            int maximumExpectedCount =
                Math.Max(0, originalCount - appliedCount);

            if (proposedCount > maximumExpectedCount)
            {
                return false;
            }
        }

        return true;
    }

    private static bool HasEquivalentStructure(
        ParsedWorkflow original,
        ParsedWorkflow proposed)
    {
        return original.Jobs.Count == proposed.Jobs.Count &&
            original.Triggers
                .OrderBy(trigger => trigger, StringComparer.Ordinal)
                .SequenceEqual(
                    proposed.Triggers.OrderBy(
                        trigger => trigger,
                        StringComparer.Ordinal),
                    StringComparer.Ordinal);
    }

    private static IReadOnlyDictionary<string, int> CountByRule(
        IEnumerable<WorkflowFinding> findings) =>
        findings
            .GroupBy(
                finding => finding.RuleId,
                StringComparer.Ordinal)
            .ToDictionary(
                group => group.Key,
                group => group.Count(),
                StringComparer.Ordinal);

    private static bool CanPatchLine(
        int? lineNumber,
        int lineCount,
        IReadOnlySet<int> semanticLineNumbers)
    {
        return lineNumber is >= 1 &&
            lineNumber <= lineCount &&
            semanticLineNumbers.Contains(lineNumber.Value);
    }

    private static string RemoveTrailingComment(string text)
    {
        int commentIndex = text.IndexOf('#');

        return commentIndex >= 0
            ? text[..commentIndex].TrimEnd()
            : text;
    }
}
