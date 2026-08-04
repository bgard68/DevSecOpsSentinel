using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Application;

public sealed class RemediationReportService(IWorkflowAnalysisService analysisService) : IRemediationReportService
{
    public RemediationReport Build(WorkflowDocument document)
    {
        WorkflowAnalysisResult original = analysisService.Analyze(document);
        string proposedContent = original.Patch?.ProposedContent ?? document.Content;
        WorkflowAnalysisResult proposed = analysisService.Analyze(new WorkflowDocument(document.FileName, proposedContent));

        HashSet<string> remaining = proposed.Findings.Select(finding => finding.RuleId).ToHashSet(StringComparer.Ordinal);
        RemediationChange[] changes = original.Findings
            .Select(finding => new RemediationChange(
                finding.RuleId,
                finding.Title,
                finding.Severity,
                !remaining.Contains(finding.RuleId),
                finding.Recommendation))
            .ToArray();

        int originalScore = CalculateRisk(original.Findings);
        int proposedScore = CalculateRisk(proposed.Findings);
        int reduction = originalScore == 0
            ? 0
            : (int)Math.Round((originalScore - proposedScore) * 100d / originalScore, MidpointRounding.AwayFromZero);

        return new RemediationReport(
            document.FileName,
            original,
            proposed,
            changes,
            BuildUnifiedDiff(document.Content, proposedContent),
            originalScore,
            proposedScore,
            Math.Clamp(reduction, 0, 100),
            original.Patch?.ProposedContentIsValid ?? original.IsValid);
    }

    private static int CalculateRisk(IEnumerable<WorkflowFinding> findings) =>
        findings.Sum(finding => finding.Severity switch
        {
            WorkflowSeverity.Critical => 10,
            WorkflowSeverity.High => 7,
            WorkflowSeverity.Medium => 4,
            WorkflowSeverity.Low => 2,
            _ => 1
        });

    private static IReadOnlyList<string> BuildUnifiedDiff(string original, string proposed)
    {
        string[] before = Normalize(original).Split('\n');
        string[] after = Normalize(proposed).Split('\n');
        List<string> diff = ["--- original", "+++ proposed"];
        int length = Math.Max(before.Length, after.Length);
        for (int index = 0; index < length; index++)
        {
            string? oldLine = index < before.Length ? before[index] : null;
            string? newLine = index < after.Length ? after[index] : null;
            if (oldLine == newLine)
            {
                diff.Add($" {oldLine}");
                continue;
            }
            if (oldLine is not null) diff.Add($"-{oldLine}");
            if (newLine is not null) diff.Add($"+{newLine}");
        }
        return diff;
    }

    private static string Normalize(string value) => value.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');
}
