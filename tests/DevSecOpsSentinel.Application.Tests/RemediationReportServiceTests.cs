using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Application.Tests;

public sealed class RemediationReportServiceTests
{
    [Fact]
    public async Task Unified_diff_contains_valid_hunk_header()
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
    public async Task Exported_patch_applies_cleanly_with_git_apply()
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
    public async Task Exported_patch_applies_when_the_workflow_has_no_final_newline()
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
    public async Task Unified_diff_names_the_workflow_being_analyzed()
    {
        RemediationReport report = await BuildReportAsync(
            "release.yml",
            "name: Build\njobs:\n  build:\n    runs-on: ubuntu-latest",
            "name: Build\njobs:\n  build:\n    timeout-minutes: 15\n    runs-on: ubuntu-latest");

        Assert.Equal("--- a/release.yml", report.UnifiedDiff[0]);
        Assert.Equal("+++ b/release.yml", report.UnifiedDiff[1]);
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
