using System.Text.RegularExpressions;
using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Rules;

public sealed partial class UnpinnedActionRule : IWorkflowSecurityRule
{
    public string RuleId => "GHA001";
    public string Title => "Action reference is not pinned to a commit SHA";
    public WorkflowSeverity Severity => WorkflowSeverity.High;

    public IReadOnlyList<WorkflowFinding> Evaluate(
        ParsedWorkflow workflow) =>
        workflow.Lines
            .Where(line =>
                line.Text.StartsWith(
                    "uses:",
                    StringComparison.Ordinal) ||
                line.Text.StartsWith(
                    "- uses:",
                    StringComparison.Ordinal))
            .Where(line => IsUnpinned(line.Text))
            .Select(line => new WorkflowFinding(
                RuleId,
                Severity,
                Title,
                "A movable tag or branch can resolve to different code in the future.",
                line.Number,
                "Pin the action to a verified 40-character commit SHA.",
                true))
            .ToArray();

    private static bool IsUnpinned(string text)
    {
        Match match = ActionReferenceRegex().Match(text);

        return match.Success &&
            !FullShaRegex().IsMatch(match.Groups[1].Value);
    }

    [GeneratedRegex(
        @"uses:\s*[^@\s]+@([^\s#]+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ActionReferenceRegex();

    [GeneratedRegex(
        "^[a-f0-9]{40}$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex FullShaRegex();
}
