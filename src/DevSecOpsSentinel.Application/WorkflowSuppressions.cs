using System.Text.RegularExpressions;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Application;

/// <summary>
/// A finding whose author has read it and accepted it, stated in the workflow
/// itself:
///
/// <code>
/// permissions:
///   # sentinel:accept GHA002 - deleting a workflow run has no narrower grant
///   actions: write
/// </code>
///
/// It lives in the workflow rather than in a separate file of rule/line/reason
/// entries on purpose. Line numbers in such a file drift the moment anyone edits
/// the workflow, the reason ends up far from the thing it explains, and the file
/// outlives the code it was written about. A comment is deleted by the same edit
/// that deletes what it annotates, and a reviewer sees it appear in the diff
/// beside what it waves away.
/// </summary>
public sealed partial class WorkflowSuppressions
{
    private readonly List<Suppression> _entries;

    private WorkflowSuppressions(List<Suppression> entries) => _entries = entries;

    /// <summary>One accepted finding: which rule, which line, and why.</summary>
    public sealed record Suppression(string RuleId, int Line, string Reason, int DirectiveLine);

    /// <summary>Directives that named a rule but gave no reason, and were ignored.</summary>
    public IReadOnlyList<int> WithoutReason { get; private init; } = [];

    public IReadOnlyList<Suppression> Entries => _entries;

    /// <summary>
    /// Reads every directive in the workflow.
    ///
    /// A directive with no reason is not honoured. Silencing a finding is a
    /// judgement, and a bare marker records that someone wanted the finding gone
    /// without recording that anyone thought about it - which is the state this
    /// whole mechanism exists to avoid. The finding keeps reporting, and the
    /// directive's line is returned so the omission can be surfaced rather than
    /// leaving the author to wonder why nothing happened.
    /// </summary>
    public static WorkflowSuppressions Read(ParsedWorkflow workflow)
    {
        List<Suppression> entries = [];
        List<int> withoutReason = [];

        foreach (WorkflowLine line in workflow.Lines)
        {
            Match match = DirectiveRegex().Match(line.Text);
            if (!match.Success)
            {
                continue;
            }

            string reason = match.Groups["reason"].Value.Trim(' ', '-', '—', ':').Trim();
            if (reason.Length == 0)
            {
                withoutReason.Add(line.Number);
                continue;
            }

            entries.Add(new Suppression(
                match.Groups["rule"].Value.ToUpperInvariant(),
                TargetLine(workflow, line),
                reason,
                line.Number));
        }

        return new WorkflowSuppressions(entries) { WithoutReason = withoutReason };
    }

    /// <summary>
    /// Whether this finding has been accepted. Matched on rule and line together:
    /// accepting GHA002 on one grant must not quietly accept a second GHA002
    /// elsewhere in the same file.
    /// </summary>
    public Suppression? For(WorkflowFinding finding) =>
        _entries.FirstOrDefault(entry =>
            entry.RuleId.Equals(finding.RuleId, StringComparison.OrdinalIgnoreCase) &&
            finding.LineNumber is { } line &&
            entry.Line == line);

    /// <summary>
    /// Directives that no longer match anything the rules reported.
    ///
    /// The reason this is reported rather than ignored: a directive that has
    /// outlived its finding is a claim, sitting in the file, that somebody
    /// considered a problem which no longer exists. It reads as considered when
    /// nothing considered it, and the next reader has no way to tell the
    /// difference. Every suppression mechanism accumulates these; reporting them
    /// is what stops the list rotting.
    /// </summary>
    public IReadOnlyList<Suppression> Stale(IEnumerable<WorkflowFinding> findings)
    {
        List<WorkflowFinding> reported = [.. findings];

        return
        [
            .. _entries.Where(entry => !reported.Any(finding =>
                entry.RuleId.Equals(finding.RuleId, StringComparison.OrdinalIgnoreCase) &&
                finding.LineNumber is { } line &&
                entry.Line == line))
        ];
    }

    /// <summary>
    /// Which line the directive is about: its own, when it trails real content,
    /// and otherwise the next line that carries any.
    /// </summary>
    private static int TargetLine(ParsedWorkflow workflow, WorkflowLine directive)
    {
        if (!directive.Text.TrimStart().StartsWith('#'))
        {
            return directive.Number;
        }

        WorkflowLine? next = workflow.Lines
            .Where(line => line.Number > directive.Number)
            .FirstOrDefault(line =>
                line.Text.Length > 0 && !line.Text.TrimStart().StartsWith('#'));

        return next?.Number ?? directive.Number;
    }

    /// <summary>
    /// <c># sentinel:accept GHA002 - reason</c>, anywhere on the line so a
    /// trailing comment works as well as one on its own line. The separator
    /// between rule and reason is optional.
    /// </summary>
    [GeneratedRegex(
        @"#\s*sentinel:accept\s+(?<rule>GHA\d{3})\b(?<reason>.*)$",
        RegexOptions.IgnoreCase)]
    private static partial Regex DirectiveRegex();
}
