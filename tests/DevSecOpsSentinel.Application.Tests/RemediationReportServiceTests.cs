using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Application.Tests;

public sealed class RemediationReportServiceTests
{
    [Fact]
    public async Task BuildAsync_PatchableWorkflow_ProducesAValidHunkHeader()
    {
        WorkflowDocument document = new(
            "build.yml",
            "name: Build\njobs:\n  build:\n    runs-on: ubuntu-latest");

        WorkflowPatch patch = new(
            document.Content,
            "name: Build\njobs:\n  build:\n    timeout-minutes: 15\n    runs-on: ubuntu-latest",
            ["GHA003"],
            true);

        WorkflowAnalysisResult original = new(
            document.FileName,
            true,
            [],
            [],
            patch);

        WorkflowAnalysisResult proposed = new(
            document.FileName,
            true,
            [],
            [],
            null);

        RemediationReportService service = new(
            new SequenceAnalysisService(original, proposed));

        RemediationReport report = await service.BuildAsync(
            document,
            CancellationToken.None);

        Assert.StartsWith(
            "@@ -1,",
            report.UnifiedDiff[2]);
        Assert.Contains(
            "+    timeout-minutes: 15",
            report.UnifiedDiff);
    }

    [Fact]
    public async Task BuildAsync_PatchableWorkflow_ProducesADiffGitApplyAccepts()
    {
        // The patch is served as text/x-diff with a .patch extension, so the
        // contract is that git accepts it. Asserting on hunk-header text alone
        // let a structurally invalid diff ship undetected for several releases.
        const string originalContent =
            "name: Build\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n";

        const string proposedContent =
            "name: Build\non:\n  push:\njobs:\n  build:\n    timeout-minutes: 15\n    runs-on: ubuntu-latest\n";

        RemediationReport report = await BuildReportAsync(
            "ci.yml",
            originalContent,
            proposedContent);

        string workspace = Path.Combine(
            Path.GetTempPath(),
            $"sentinel-patch-{Guid.NewGuid():N}");

        Directory.CreateDirectory(workspace);

        try
        {
            RunGit(workspace, "init", "--quiet");

            string targetPath = Path.Combine(workspace, "ci.yml");
            await File.WriteAllTextAsync(targetPath, originalContent);

            string patchPath = Path.Combine(workspace, "remediation.patch");
            await File.WriteAllTextAsync(
                patchPath,
                string.Join("\n", report.UnifiedDiff) + "\n");

            (int exitCode, string output) = RunGit(
                workspace,
                "apply",
                "--verbose",
                "remediation.patch");

            Assert.True(
                exitCode == 0,
                $"git apply rejected the exported patch:\n{output}");

            string applied = await File.ReadAllTextAsync(targetPath);

            Assert.Equal(
                proposedContent.Replace("\r\n", "\n", StringComparison.Ordinal),
                applied.Replace("\r\n", "\n", StringComparison.Ordinal));
        }
        finally
        {
            Directory.Delete(workspace, recursive: true);
        }
    }

    [Fact]
    public async Task BuildAsync_WorkflowWithoutAFinalNewline_ProducesADiffGitApplyAccepts()
    {
        const string originalContent =
            "name: Build\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest";

        const string proposedContent =
            "name: Build\non:\n  push:\njobs:\n  build:\n    timeout-minutes: 15\n    runs-on: ubuntu-latest";

        RemediationReport report = await BuildReportAsync(
            "ci.yml",
            originalContent,
            proposedContent);

        Assert.Contains(
            "\\ No newline at end of file",
            report.UnifiedDiff);

        string workspace = Path.Combine(
            Path.GetTempPath(),
            $"sentinel-patch-{Guid.NewGuid():N}");

        Directory.CreateDirectory(workspace);

        try
        {
            RunGit(workspace, "init", "--quiet");

            string targetPath = Path.Combine(workspace, "ci.yml");
            await File.WriteAllTextAsync(targetPath, originalContent);

            await File.WriteAllTextAsync(
                Path.Combine(workspace, "remediation.patch"),
                string.Join("\n", report.UnifiedDiff) + "\n");

            (int exitCode, string output) = RunGit(
                workspace,
                "apply",
                "--verbose",
                "remediation.patch");

            Assert.True(
                exitCode == 0,
                $"git apply rejected the exported patch:\n{output}");

            Assert.Equal(
                proposedContent,
                (await File.ReadAllTextAsync(targetPath))
                    .Replace("\r\n", "\n", StringComparison.Ordinal));
        }
        finally
        {
            Directory.Delete(workspace, recursive: true);
        }
    }

    [Fact]
    public async Task BuildAsync_NamedWorkflow_NamesThatFileInTheDiffHeader()
    {
        RemediationReport report = await BuildReportAsync(
            "release.yml",
            "name: Build\njobs:\n  build:\n    runs-on: ubuntu-latest",
            "name: Build\njobs:\n  build:\n    timeout-minutes: 15\n    runs-on: ubuntu-latest");

        Assert.Equal("--- a/release.yml", report.UnifiedDiff[0]);
        Assert.Equal("+++ b/release.yml", report.UnifiedDiff[1]);
    }

    [Fact]
    public async Task BuildAsync_EveryFinding_ProducesExactlyOneChangeInOrderCarryingItsLine()
    {
        // The invariant the export layer relies on. It used to pair findings to changes by
        // index on the strength of a comment; this is the thing that comment asserted, now
        // held where it is produced.
        WorkflowFinding[] findings =
        [
            Finding("GHA001", WorkflowSeverity.High, 7, "First"),
            Finding("GHA001", WorkflowSeverity.High, 12, "Second"),
            Finding("GHA003", WorkflowSeverity.Low, 3, "Third")
        ];

        RemediationReport report = await BuildAsync(
            Analysis(findings, Patch(valid: true, applied: [])),
            Analysis(findings));

        Assert.Equal(findings.Length, report.Changes.Count);

        Assert.Equal(
            findings.Select(finding => (finding.RuleId, finding.LineNumber, finding.Title)),
            report.Changes.Select(change => (change.RuleId, change.LineNumber, change.Title)));
    }

    [Fact]
    public async Task BuildAsync_OneOfTwoFindingsOfTheSameRuleFixed_ReportsOnlyThatOneResolved()
    {
        /*
         * The defect this closes. Resolution was inferred from which rule ids survived
         * re-analysis, so fixing one of two unpinned actions — the other's reference being
         * unresolvable — left GHA001 in the surviving set and reported both as unresolved.
         * The panel read "Resolved: 0" beside a diff that visibly pinned one action.
         */
        WorkflowFinding fixedFinding = Finding("GHA001", WorkflowSeverity.High, 7, "Pinned");
        WorkflowFinding unfixedFinding = Finding("GHA001", WorkflowSeverity.High, 12, "Unresolvable");

        RemediationReport report = await BuildAsync(
            Analysis(
                [fixedFinding, unfixedFinding],
                Patch(valid: true, applied: [fixedFinding])),
            // GHA001 still reports, because one of the two was left untouched.
            Analysis([unfixedFinding]));

        Assert.Collection(
            report.Changes,
            change => Assert.True(change.Resolved, "The fixed finding should be resolved."),
            change => Assert.False(change.Resolved, "The untouched finding should not be resolved."));

        Assert.Equal(1, report.ResolvedFindingCount);
    }

    [Fact]
    public async Task BuildAsync_InvalidPatch_ClaimsNoReductionResolvesNothingAndProposesNoChange()
    {
        /*
         * An invalid patch is most often one that no longer parses, and an unparseable
         * document reports no findings. That arrived as a proposed risk score of zero and
         * was printed as a 100% risk reduction, in the same report that declared the patch
         * invalid. Nothing is claimed for a patch that will not be offered.
         */
        WorkflowFinding finding = Finding("GHA002", WorkflowSeverity.High, 4, "Excessive");

        RecordingAnalysisService analysisService = new(
            Analysis(
                [finding],
                Patch(valid: false, applied: [finding], proposedContent: "not: [valid")),
            // What re-analysing the unchanged document returns.
            Analysis([finding]));

        RemediationReport report = await new RemediationReportService(analysisService)
            .BuildAsync(new WorkflowDocument("build.yml", OriginalContent), CancellationToken.None);

        Assert.Equal(0, report.RiskReductionPercent);
        Assert.Equal(0, report.ResolvedFindingCount);
        Assert.False(report.PatchValid);
        Assert.All(report.Changes, change => Assert.False(change.Resolved));

        // The proposal is the document as it stands, so the second analysis sees the
        // original content rather than the rejected patch.
        Assert.Equal(2, analysisService.Documents.Count);
        Assert.Equal(OriginalContent, analysisService.Documents[1].Content);

        // An empty diff body: three header lines and nothing claimed below them.
        Assert.DoesNotContain(report.UnifiedDiff, line => line.StartsWith('+') && !line.StartsWith("+++"));
        Assert.DoesNotContain(report.UnifiedDiff, line => line.StartsWith('-') && !line.StartsWith("---"));
    }

    [Fact]
    public async Task BuildAsync_LargeDocumentWithOneChange_DiffsOnlyThatLine()
    {
        /*
         * Identical leading and trailing lines are taken as context without entering the
         * comparison table, so the cost is quadratic in the size of the edit rather than the
         * size of the file.
         *
         * Measured on the previous implementation, a document of this size allocated 138 MB
         * to diff a single changed line, and the cost was quadratic: the 100,000-character
         * request limit admits around 50,000 lines, which would have asked for roughly 9 GB.
         * The deployment target has 1 GB for the whole host.
         */
        string original = LargeDocument(6_000, changeEveryThirdLine: false);
        string proposed = original.Replace(
            "  key4000: value",
            "  key4000: changed",
            StringComparison.Ordinal);

        RemediationReport report = await BuildReportAsync("big.yml", original, proposed);

        Assert.Equal(
            1,
            report.UnifiedDiff.Count(line =>
                line.StartsWith("-  key", StringComparison.Ordinal)));

        Assert.Equal(
            1,
            report.UnifiedDiff.Count(line =>
                line.StartsWith("+  key", StringComparison.Ordinal)));

        Assert.Contains("+  key4000: changed", report.UnifiedDiff);
    }

    [Fact]
    public async Task BuildAsync_ScatteredChangesBeyondTheBudget_ReplacesTheRegionWholesale()
    {
        /*
         * The bound, from the other side. Changes every third line, so the identical head
         * and tail are one line each and the region to compare is the whole document —
         * which is the input the memory budget exists for.
         *
         * Asserted structurally rather than by measuring bytes: a wholesale replacement
         * emits every removal before every addition, whereas a line-by-line comparison
         * interleaves them. An allocation assertion would be read from a process-wide
         * counter that other tests running in parallel also move.
         */
        string original = LargeDocument(6_000, changeEveryThirdLine: false);
        string proposed = LargeDocument(6_000, changeEveryThirdLine: true);

        RemediationReport report = await BuildReportAsync("big.yml", original, proposed);

        string[] body = [.. report.UnifiedDiff.Skip(3)];

        int lastRemoval = Array.FindLastIndex(
            body,
            line => line.StartsWith('-'));

        int firstAddition = Array.FindIndex(
            body,
            line => line.StartsWith('+'));

        Assert.True(
            lastRemoval >= 0 && firstAddition >= 0,
            "The diff should contain both removals and additions.");

        Assert.True(
            lastRemoval < firstAddition,
            "Beyond the comparison budget the region is replaced wholesale, so every "
            + $"removal precedes every addition. Last removal {lastRemoval}, first "
            + $"addition {firstAddition}.");
    }

    [Fact]
    public async Task BuildAsync_ScatteredChangesBeyondTheBudget_StillProducesADiffGitApplyAccepts()
    {
        // The fallback trades a readable diff for a bounded one. It must not trade away the
        // property that the export is a patch git accepts, which is the contract entry 2 of
        // the engineering log was written about.
        string original = LargeDocument(2_500, changeEveryThirdLine: false);
        string proposed = LargeDocument(2_500, changeEveryThirdLine: true);

        RemediationReport report = await BuildReportAsync("big.yml", original, proposed);

        await AssertGitAppliesAsync("big.yml", original, proposed, report);
    }

    [Fact]
    public async Task BuildAsync_ProposedContentIdenticalToTheOriginal_ClaimsNoChange()
    {
        // The edge case the head and tail trimming has to get right: with every line
        // matching, the two runs must not both claim the same lines.
        string original = LargeDocument(200, changeEveryThirdLine: false);

        RemediationReport report = await BuildReportAsync("same.yml", original, original);

        Assert.DoesNotContain(
            report.UnifiedDiff,
            line => line.StartsWith('+') && !line.StartsWith("+++", StringComparison.Ordinal));

        Assert.DoesNotContain(
            report.UnifiedDiff,
            line => line.StartsWith('-') && !line.StartsWith("---", StringComparison.Ordinal));

        // Every line still appears as context, so the hunk covers the whole document.
        Assert.Equal(200, report.UnifiedDiff.Count(line => line.StartsWith(' ')));
    }

    private static string LargeDocument(int lines, bool changeEveryThirdLine) =>
        string.Join(
            "\n",
            Enumerable.Range(0, lines).Select(index =>
                changeEveryThirdLine && index % 3 == 1
                    ? $"  key{index}: changed"
                    : $"  key{index}: value")) + "\n";

    /// <summary>
    /// Writes the original, applies the exported patch with git, and asserts the result is
    /// the proposed document.
    /// </summary>
    private static async Task AssertGitAppliesAsync(
        string fileName,
        string original,
        string proposed,
        RemediationReport report)
    {
        string workspace = Path.Combine(
            Path.GetTempPath(),
            $"sentinel-patch-{Guid.NewGuid():N}");

        Directory.CreateDirectory(workspace);

        try
        {
            RunGit(workspace, "init", "--quiet");

            string targetPath = Path.Combine(workspace, fileName);
            await File.WriteAllTextAsync(targetPath, original);

            await File.WriteAllTextAsync(
                Path.Combine(workspace, "remediation.patch"),
                string.Join("\n", report.UnifiedDiff) + "\n");

            (int exitCode, string output) = RunGit(
                workspace,
                "apply",
                "--verbose",
                "remediation.patch");

            Assert.True(
                exitCode == 0,
                $"git apply rejected the exported patch:\n{output}");

            Assert.Equal(
                proposed.Replace("\r\n", "\n", StringComparison.Ordinal),
                (await File.ReadAllTextAsync(targetPath))
                    .Replace("\r\n", "\n", StringComparison.Ordinal));
        }
        finally
        {
            Directory.Delete(workspace, recursive: true);
        }
    }

    private const string OriginalContent =
        "name: Build\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n";

    private static WorkflowFinding Finding(
        string ruleId,
        WorkflowSeverity severity,
        int? line,
        string title) =>
        new(ruleId, severity, title, $"{title} description", line, $"{title} recommendation", true);

    private static WorkflowPatch Patch(
        bool valid,
        IReadOnlyList<WorkflowFinding> applied,
        string? proposedContent = null) =>
        new(
            OriginalContent,
            proposedContent ?? OriginalContent,
            [.. applied.Select(finding => finding.RuleId).Distinct(StringComparer.Ordinal)],
            valid)
        {
            AppliedFindings = applied
        };

    private static WorkflowAnalysisResult Analysis(
        IReadOnlyList<WorkflowFinding> findings,
        WorkflowPatch? patch = null) =>
        new("build.yml", true, [], findings, patch);

    private static async Task<RemediationReport> BuildAsync(
        WorkflowAnalysisResult original,
        WorkflowAnalysisResult proposed) =>
        await new RemediationReportService(new SequenceAnalysisService(original, proposed))
            .BuildAsync(new WorkflowDocument("build.yml", OriginalContent), CancellationToken.None);

    /// <summary>
    /// Records the documents it was asked to analyse, so a test can assert which content the
    /// service treated as the proposal.
    /// </summary>
    private sealed class RecordingAnalysisService(params WorkflowAnalysisResult[] results)
        : IWorkflowAnalysisService
    {
        private int _index;

        public List<WorkflowDocument> Documents { get; } = [];

        public Task<WorkflowAnalysisResult> AnalyzeAsync(
            WorkflowDocument document,
            CancellationToken cancellationToken)
        {
            Documents.Add(document);
            WorkflowAnalysisResult result = results[Math.Min(_index, results.Length - 1)];
            _index++;

            return Task.FromResult(result);
        }
    }

    private static async Task<RemediationReport> BuildReportAsync(
        string fileName,
        string originalContent,
        string proposedContent)
    {
        WorkflowDocument document = new(fileName, originalContent);

        WorkflowPatch patch = new(
            originalContent,
            proposedContent,
            ["GHA003"],
            true);

        WorkflowAnalysisResult original = new(fileName, true, [], [], patch);
        WorkflowAnalysisResult proposed = new(fileName, true, [], [], null);

        RemediationReportService service = new(
            new SequenceAnalysisService(original, proposed));

        return await service.BuildAsync(document, CancellationToken.None);
    }

    private static (int ExitCode, string Output) RunGit(
        string workingDirectory,
        params string[] arguments)
    {
        System.Diagnostics.ProcessStartInfo startInfo = new("git")
        {
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };

        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using System.Diagnostics.Process process =
            System.Diagnostics.Process.Start(startInfo)
            ?? throw new InvalidOperationException("git could not be started.");

        string output =
            process.StandardOutput.ReadToEnd() +
            process.StandardError.ReadToEnd();

        process.WaitForExit();

        return (process.ExitCode, output);
    }

    private sealed class SequenceAnalysisService(
        params WorkflowAnalysisResult[] results)
        : IWorkflowAnalysisService
    {
        private int _index;

        public Task<WorkflowAnalysisResult> AnalyzeAsync(
            WorkflowDocument document,
            CancellationToken cancellationToken)
        {
            WorkflowAnalysisResult result =
                results[Math.Min(_index, results.Length - 1)];

            _index++;
            return Task.FromResult(result);
        }
    }
}
