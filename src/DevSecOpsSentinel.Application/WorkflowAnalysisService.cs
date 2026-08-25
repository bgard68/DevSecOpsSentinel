using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Application;

public sealed class WorkflowAnalysisService(
    IWorkflowParser parser,
    IEnumerable<IWorkflowSecurityRule> rules,
    IWorkflowPatchGenerator patchGenerator)
    : IWorkflowAnalysisService
{
    /// <summary>
    /// Reported against the acceptance mechanism itself rather than any workflow
    /// rule, so a stale or unexplained directive cannot be mistaken for the
    /// finding it refers to.
    /// </summary>
    private const string StaleSuppressionRuleId = "GHA012";

    public async Task<WorkflowAnalysisResult> AnalyzeAsync(
        WorkflowDocument document,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(document);

        WorkflowParseResult parseResult = parser.Parse(document);
        if (!parseResult.IsValid || parseResult.Workflow is null)
        {
            return new WorkflowAnalysisResult(
                document.FileName,
                false,
                parseResult.Errors,
                Array.Empty<WorkflowFinding>(),
                null);
        }

        WorkflowFinding[] findings = rules
            .SelectMany(rule => rule.Evaluate(parseResult.Workflow))
            .OrderByDescending(finding => finding.Severity)
            .ThenBy(finding =>
                finding.LineNumber ?? int.MaxValue)
            .ThenBy(
                finding => finding.RuleId,
                StringComparer.Ordinal)
            .ToArray();

        // Findings the author has read and accepted move out of the reported set
        // and into the accepted one, keeping their severity and gaining the
        // reason. Nothing is discarded: a suppressed Critical is still visible,
        // it is just no longer counted as outstanding work.
        WorkflowSuppressions suppressions = WorkflowSuppressions.Read(parseResult.Workflow);

        List<WorkflowAcknowledgement> accepted = [];
        List<WorkflowFinding> reported = [];

        foreach (WorkflowFinding finding in findings)
        {
            if (suppressions.For(finding) is { } suppression)
            {
                accepted.Add(new WorkflowAcknowledgement(
                    finding.RuleId,
                    $"{finding.Title} - accepted",
                    $"{suppression.Reason} (accepted in the workflow, line "
                        + $"{suppression.DirectiveLine}; severity was {finding.Severity})",
                    finding.LineNumber,
                    WorkflowAcceptedBy.Author));
                continue;
            }

            reported.Add(finding);
        }

        // A directive that matches nothing is a claim in the file that someone
        // considered a problem which is no longer there. Reported so the list
        // cannot rot into decoration.
        foreach (WorkflowSuppressions.Suppression stale in suppressions.Stale(findings))
        {
            reported.Add(new WorkflowFinding(
                StaleSuppressionRuleId,
                WorkflowSeverity.Low,
                "Accepted finding no longer exists",
                $"This line accepts {stale.RuleId}, but no {stale.RuleId} finding is "
                    + "reported here any more. An acceptance that has outlived its "
                    + "finding reads as considered when nothing considered it.",
                stale.DirectiveLine,
                "Delete the sentinel:accept comment, or correct the rule it names.",
                false));
        }

        // Named but unexplained: honouring these would let a bare marker silence
        // a finding, which is the mute button this mechanism exists instead of.
        foreach (int line in suppressions.WithoutReason)
        {
            reported.Add(new WorkflowFinding(
                StaleSuppressionRuleId,
                WorkflowSeverity.Low,
                "Acceptance has no stated reason",
                "A sentinel:accept comment gives no reason, so it was ignored and "
                    + "the finding it names still reports.",
                line,
                "State why the finding is acceptable after the rule id, or remove "
                    + "the comment.",
                false));
        }

        findings = [.. reported
            .OrderByDescending(finding => finding.Severity)
            .ThenBy(finding => finding.LineNumber ?? int.MaxValue)
            .ThenBy(finding => finding.RuleId, StringComparer.Ordinal)];

        WorkflowPatch patch =
            await patchGenerator.GenerateAsync(
                parseResult.Workflow,
                findings,
                cancellationToken);

        WorkflowAcknowledgement[] acknowledgements = rules
            .SelectMany(rule => rule.Acknowledge(parseResult.Workflow))
            .Concat(accepted)
            .OrderBy(entry => entry.LineNumber ?? int.MaxValue)
            .ThenBy(entry => entry.RuleId, StringComparer.Ordinal)
            .ToArray();

        return new WorkflowAnalysisResult(
            document.FileName,
            true,
            Array.Empty<string>(),
            findings,
            patch)
        {
            Acknowledgements = acknowledgements
        };
    }
}
