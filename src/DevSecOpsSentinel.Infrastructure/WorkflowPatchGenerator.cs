using System.Text.RegularExpressions;
using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;
using DevSecOpsSentinel.Infrastructure.GitHub;

namespace DevSecOpsSentinel.Infrastructure;

public sealed partial class WorkflowPatchGenerator(
    IWorkflowParser parser,
    IEnumerable<IWorkflowSecurityRule> rules,
    IWorkflowActionReferenceResolver actionReferenceResolver,
    GitHubOptions gitHubOptions)
    : IWorkflowPatchGenerator
{
    private readonly IReadOnlyList<IWorkflowSecurityRule> _rules =
        rules.ToArray();

    public async Task<WorkflowPatch> GenerateAsync(
        ParsedWorkflow workflow,
        IReadOnlyList<WorkflowFinding> findings,
        CancellationToken cancellationToken)
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
        List<string> resolutionWarnings = [];

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
                Match match = ActionReferenceRegex().Match(lines[index]);
                if (!match.Success)
                {
                    continue;
                }

                string actionReference =
                    match.Groups["reference"].Value;

                if (!gitHubOptions.ResolveActionReferences)
                {
                    resolutionWarnings.Add(
                        $"Line {finding.LineNumber}: '{actionReference}' was not pinned because GitHub action reference resolution is disabled.");
                    continue;
                }

                ActionReferenceResolutionResult resolution =
                    await actionReferenceResolver.ResolveAsync(
                        actionReference,
                        cancellationToken);

                if (!resolution.IsResolved ||
                    !IsFullCommitSha(resolution.CommitSha))
                {
                    resolutionWarnings.Add(
                        $"Line {finding.LineNumber}: {resolution.Message}");
                    continue;
                }

                lines[index] =
                    lines[index][..match.Groups["version"].Index] +
                    resolution.CommitSha +
                    lines[index][
                        (match.Groups["version"].Index +
                         match.Groups["version"].Length)..];

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
            proposedContentIsValid)
        {
            ReferenceResolutionWarnings = resolutionWarnings
        };
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
            int originalCount =
                originalCounts.GetValueOrDefault(ruleId);
            int appliedCount =
                appliedCounts.GetValueOrDefault(ruleId);
            int proposedCount =
                proposedCounts.GetValueOrDefault(ruleId);

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
        // Job counts come from the parsed structure, the same source the rules
        // read, so patch validation and detection cannot disagree about what a
        // job is.
        return original.Structure.Jobs.Count == proposed.Structure.Jobs.Count &&
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

    private static bool IsFullCommitSha(string? value) =>
        value is not null &&
        value.Length == 40 &&
        value.All(character =>
            character is >= '0' and <= '9' ||
            character is >= 'a' and <= 'f' ||
            character is >= 'A' and <= 'F');

    private static string RemoveTrailingComment(string text)
    {
        int commentIndex = text.IndexOf('#');

        return commentIndex >= 0
            ? text[..commentIndex].TrimEnd()
            : text;
    }

    [GeneratedRegex(
        @"uses:\s*(?<reference>[^@\s#]+@(?<version>[^\s#]+))",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ActionReferenceRegex();
}
