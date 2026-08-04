using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Domain.Tests;

public sealed class WorkflowAnalysisResultTests
{
    [Fact]
    public void Finding_count_matches_findings()
    {
        WorkflowFinding finding = new(
            "GHA001",
            WorkflowSeverity.High,
            "Title",
            "Description",
            1,
            "Recommendation",
            true);

        WorkflowAnalysisResult result = new(
            "build.yml",
            true,
            Array.Empty<string>(),
            [finding],
            null);

        Assert.Equal(1, result.FindingCount);
    }
}
