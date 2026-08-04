using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Application;

public sealed class RemediationReportService(
    IWorkflowAnalysisService analysisService)
    : IRemediationReportService
{
    public async Task<RemediationReport> BuildAsync(
        WorkflowDocument document,
        CancellationToken cancellationToken)
    {
        WorkflowAnalysisResult original =
            await analysisService.AnalyzeAsync(
                document,
                cancellationToken);

        string proposedContent =
            original.Patch?.ProposedContent ?? document.Content;

        WorkflowAnalysisResult proposed =
            await analysisService.AnalyzeAsync(
                new WorkflowDocument(
                    document.FileName,
                    proposedContent),
                cancellationToken);

        HashSet<string> remaining = proposed.Findings
            .Select(finding => finding.RuleId)
            .ToHashSet(StringComparer.Ordinal);

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
            : (int)Math.Round(
                (originalScore - proposedScore) *
                100d /
                originalScore,
                MidpointRounding.AwayFromZero);

        return new RemediationReport(
            document.FileName,
            original,
            proposed,
            changes,
            BuildUnifiedDiff(
                document.Content,
                proposedContent),
            originalScore,
            proposedScore,
            Math.Clamp(reduction, 0, 100),
            original.Patch?.ProposedContentIsValid ??
            original.IsValid);
    }

    private static int CalculateRisk(
        IEnumerable<WorkflowFinding> findings) =>
        findings.Sum(finding =>
            finding.Severity switch
            {
                WorkflowSeverity.Critical => 10,
                WorkflowSeverity.High => 7,
                WorkflowSeverity.Medium => 4,
                WorkflowSeverity.Low => 2,
                _ => 1
            });

    private static IReadOnlyList<string> BuildUnifiedDiff(
        string original,
        string proposed)
    {
        string[] before = Normalize(original).Split('\n');
        string[] after = Normalize(proposed).Split('\n');

        int[,] lengths = BuildLongestCommonSubsequenceTable(
            before,
            after);

        List<string> body = [];
        int beforeIndex = 0;
        int afterIndex = 0;

        while (beforeIndex < before.Length &&
               afterIndex < after.Length)
        {
            if (string.Equals(
                before[beforeIndex],
                after[afterIndex],
                StringComparison.Ordinal))
            {
                body.Add($" {before[beforeIndex]}");
                beforeIndex++;
                afterIndex++;
            }
            else if (
                lengths[beforeIndex + 1, afterIndex] >=
                lengths[beforeIndex, afterIndex + 1])
            {
                body.Add($"-{before[beforeIndex]}");
                beforeIndex++;
            }
            else
            {
                body.Add($"+{after[afterIndex]}");
                afterIndex++;
            }
        }

        while (beforeIndex < before.Length)
        {
            body.Add($"-{before[beforeIndex++]}");
        }

        while (afterIndex < after.Length)
        {
            body.Add($"+{after[afterIndex++]}");
        }

        List<string> diff =
        [
            "--- a/workflow.yml",
            "+++ b/workflow.yml",
            $"@@ -1,{before.Length} +1,{after.Length} @@"
        ];

        diff.AddRange(body);
        return diff;
    }

    private static int[,] BuildLongestCommonSubsequenceTable(
        IReadOnlyList<string> before,
        IReadOnlyList<string> after)
    {
        int[,] lengths =
            new int[before.Count + 1, after.Count + 1];

        for (int beforeIndex = before.Count - 1;
             beforeIndex >= 0;
             beforeIndex--)
        {
            for (int afterIndex = after.Count - 1;
                 afterIndex >= 0;
                 afterIndex--)
            {
                lengths[beforeIndex, afterIndex] =
                    string.Equals(
                        before[beforeIndex],
                        after[afterIndex],
                        StringComparison.Ordinal)
                    ? lengths[
                        beforeIndex + 1,
                        afterIndex + 1] + 1
                    : Math.Max(
                        lengths[beforeIndex + 1, afterIndex],
                        lengths[beforeIndex, afterIndex + 1]);
            }
        }

        return lengths;
    }

    private static string Normalize(string value) =>
        value
            .Replace(
                "\r\n",
                "\n",
                StringComparison.Ordinal)
            .Replace('\r', '\n');
}
