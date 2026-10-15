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
        ArgumentNullException.ThrowIfNull(document);

        WorkflowAnalysisResult original =
            await analysisService.AnalyzeAsync(
                document,
                cancellationToken);

        /*
         * A patch that failed its own validation is not offered as an improvement.
         *
         * The proposed content used to be analysed whether or not it passed, and the most
         * common reason it fails is that it no longer parses — which yields an analysis with
         * no findings at all. That arrived in the report as a risk score of zero, printed as
         * a 100% risk reduction, directly beside the same report declaring the patch invalid.
         *
         * With no usable patch the proposal is the document as it stands: nothing resolved,
         * no reduction claimed, an empty diff. Failing closed is the same choice the patch
         * generator makes when it cannot resolve an action reference.
         */
        WorkflowPatch? usablePatch =
            original.Patch is { ProposedContentIsValid: true }
                ? original.Patch
                : null;

        string proposedContent =
            usablePatch?.ProposedContent ?? document.Content;

        WorkflowAnalysisResult proposed =
            await analysisService.AnalyzeAsync(
                new WorkflowDocument(
                    document.FileName,
                    proposedContent),
                cancellationToken);

        /*
         * Resolution is read from the patch, which recorded the findings it edited, rather
         * than inferred from which rule ids survive re-analysis.
         *
         * The inference could not distinguish two findings of one rule. Fixing one of two
         * unpinned actions — the other's reference being unresolvable — left GHA001 in the
         * surviving set, so both findings were reported unresolved and the "Resolved" count
         * read zero while the diff beside it showed the pin that had been applied.
         */
        HashSet<WorkflowFinding> appliedFindings =
            [.. usablePatch?.AppliedFindings ?? []];

        RemediationChange[] changes = original.Findings
            .Select(finding => new RemediationChange(
                finding.RuleId,
                finding.Title,
                finding.Severity,
                finding.LineNumber,
                finding.Description,
                finding.Recommendation,
                appliedFindings.Contains(finding)))
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

    /// <summary>
    /// The largest line-comparison table the diff will allocate, in cells.
    ///
    /// The table is <see cref="int"/>-sized, so this budget is 16 MB. The cost is quadratic
    /// in the number of lines compared, measured on this code: 2,000 lines allocated 15 MB,
    /// 4,000 allocated 61 MB, and 6,000 allocated 138 MB. The request body limit of 100,000
    /// characters admits roughly 50,000 lines of YAML, which would ask for about 9 GB.
    ///
    /// The deployment target is an Azure App Service free tier with 1 GB for the entire
    /// host, so an unbounded table is a denial of service reachable from a single request —
    /// and the request need not be malicious, only large.
    ///
    /// Above the budget the changed region is emitted as a wholesale replacement. That is a
    /// larger diff to read and still a valid one that applies to the same document, which is
    /// the trade this makes: a less helpful patch rather than an exhausted host. Trimming
    /// the identical head and tail first (see <see cref="BuildBody"/>) keeps every realistic
    /// workflow well inside the budget, so the fallback is reached only by documents whose
    /// changes are scattered across thousands of lines.
    /// </summary>
    private const long MaximumComparisonCells = 4_000_000;

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

        List<string> body = BuildBody(before, after);

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

    /// <summary>
    /// The hunk body: context, removals and additions covering the whole document.
    ///
    /// Identical leading and trailing lines are context whatever a comparison decides about
    /// them, so they are taken directly and kept out of the table. A remediation patch
    /// changes a handful of lines in an otherwise identical document, so this is what makes
    /// the cost quadratic in the size of the edit rather than in the size of the file — a
    /// one-line change in a 10,000-line workflow now compares one line against one line.
    /// </summary>
    private static List<string> BuildBody(string[] before, string[] after)
    {
        int prefix = CommonPrefixLength(before, after);
        int suffix = CommonSuffixLength(before, after, prefix);

        int beforeChanged = before.Length - prefix - suffix;
        int afterChanged = after.Length - prefix - suffix;

        List<string> body = new(before.Length + after.Length);

        for (int index = 0; index < prefix; index++)
        {
            body.Add($" {before[index]}");
        }

        if ((long)beforeChanged * afterChanged > MaximumComparisonCells)
        {
            // Beyond the memory budget, so the region is replaced rather than compared. See
            // MaximumComparisonCells for why a worse diff is preferred to a worse host.
            for (int index = 0; index < beforeChanged; index++)
            {
                body.Add($"-{before[prefix + index]}");
            }

            for (int index = 0; index < afterChanged; index++)
            {
                body.Add($"+{after[prefix + index]}");
            }
        }
        else
        {
            body.AddRange(
                DiffChangedRegion(
                    before[prefix..(prefix + beforeChanged)],
                    after[prefix..(prefix + afterChanged)]));
        }

        for (int index = before.Length - suffix; index < before.Length; index++)
        {
            body.Add($" {before[index]}");
        }

        return body;
    }

    private static int CommonPrefixLength(string[] before, string[] after)
    {
        int limit = Math.Min(before.Length, after.Length);
        int length = 0;

        while (length < limit &&
            string.Equals(before[length], after[length], StringComparison.Ordinal))
        {
            length++;
        }

        return length;
    }

    /// <summary>
    /// Identical trailing lines, counted no further back than
    /// <paramref name="prefix"/> so the two runs cannot overlap and claim the same line
    /// twice — which is what a document identical on both sides would otherwise do.
    /// </summary>
    private static int CommonSuffixLength(string[] before, string[] after, int prefix)
    {
        int limit = Math.Min(before.Length, after.Length) - prefix;
        int length = 0;

        while (length < limit &&
            string.Equals(
                before[^(length + 1)],
                after[^(length + 1)],
                StringComparison.Ordinal))
        {
            length++;
        }

        return length;
    }

    /// <summary>
    /// Line-by-line comparison of the region that actually differs, by longest common
    /// subsequence, so a changed line reads as one removal and one addition rather than the
    /// whole region being replaced.
    /// </summary>
    private static List<string> DiffChangedRegion(string[] before, string[] after)
    {
        int[,] lengths = BuildLongestCommonSubsequenceTable(before, after);

        List<string> body = new(before.Length + after.Length);
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

        return body;
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
