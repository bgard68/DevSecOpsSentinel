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
