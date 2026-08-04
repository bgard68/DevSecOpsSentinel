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
                document.FileName,
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
        string fileName,
        string original,
        string proposed)
    {
        string normalizedOriginal = Normalize(original);
        string normalizedProposed = Normalize(proposed);

        /*
         * A file ending in a newline has N lines, but splitting it on '\n'
         * yields N + 1 elements with a trailing empty string. Emitting that
         * phantom line made git search for a blank final line that is not in
         * the file, so every exported patch was rejected with "patch does not
         * apply". The terminator is recorded here and re-expressed below as the
         * "\ No newline at end of file" marker when a side genuinely lacks it.
         */
        bool originalEndsWithNewline = normalizedOriginal.EndsWith('\n');
        bool proposedEndsWithNewline = normalizedProposed.EndsWith('\n');

        string[] before = SplitContentLines(normalizedOriginal);
        string[] after = SplitContentLines(normalizedProposed);

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

        AppendMissingNewlineMarkers(
            body,
            originalEndsWithNewline,
            proposedEndsWithNewline);

        // The export is served as a .patch file, so these headers must name the
        // workflow actually being analysed. A fixed name made `git apply` fail
        // with "No such file or directory" for every workflow not called
        // workflow.yml.
        List<string> diff =
        [
            $"--- a/{fileName}",
            $"+++ b/{fileName}",
            $"@@ -{FormatRange(before.Length)} +{FormatRange(after.Length)} @@"
        ];

        diff.AddRange(body);
        return diff;
    }

    private static string FormatRange(int lineCount) =>
        lineCount == 0 ? "0,0" : $"1,{lineCount}";

    private static string[] SplitContentLines(string value)
    {
        if (value.Length == 0)
        {
            return [];
        }

        string content = value.EndsWith('\n')
            ? value[..^1]
            : value;

        return content.Split('\n');
    }

    /// <summary>
    /// Adds the "\ No newline at end of file" marker after the final line of
    /// whichever side lacks a terminating newline. When both sides lack it and
    /// the final line is shared context, a single marker covers both.
    /// </summary>
    private static void AppendMissingNewlineMarkers(
        List<string> body,
        bool originalEndsWithNewline,
        bool proposedEndsWithNewline)
    {
        const string marker = "\\ No newline at end of file";

        if (originalEndsWithNewline && proposedEndsWithNewline)
        {
            return;
        }

        int beforeLast = originalEndsWithNewline
            ? -1
            : FindLastIndex(body, line => line[0] is ' ' or '-');

        int afterLast = proposedEndsWithNewline
            ? -1
            : FindLastIndex(body, line => line[0] is ' ' or '+');

        // Insert the later position first so the earlier index stays valid.
        foreach (int index in new[] { beforeLast, afterLast }
            .Where(index => index >= 0)
            .Distinct()
            .OrderByDescending(index => index))
        {
            body.Insert(index + 1, marker);
        }
    }

    private static int FindLastIndex(
        List<string> body,
        Func<string, bool> predicate)
    {
        for (int index = body.Count - 1; index >= 0; index--)
        {
            if (body[index].Length > 0 && predicate(body[index]))
            {
                return index;
            }
        }

        return -1;
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
