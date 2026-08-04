using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Application.Tests;

public sealed class WorkflowAnalysisServiceTests
{
    [Fact]
    public async Task Invalid_parse_result_is_returned_without_executing_rules()
    {
        StubParser parser = new();

        WorkflowAnalysisService service = new(
            parser,
            Array.Empty<IWorkflowSecurityRule>(),
            new StubPatchGenerator());

        WorkflowAnalysisResult result =
            await service.AnalyzeAsync(
                new WorkflowDocument("bad.yml", "invalid"),
                CancellationToken.None);

        Assert.False(result.IsValid);
        Assert.Single(result.ValidationErrors);
        Assert.Empty(result.Findings);
        Assert.Null(result.Patch);
    }

    private sealed class StubParser : IWorkflowParser
    {
        public WorkflowParseResult Parse(
            WorkflowDocument document) =>
            WorkflowParseResult.Failure(
                "Invalid workflow.");
    }

    private sealed class StubPatchGenerator :
        IWorkflowPatchGenerator
    {
        public Task<WorkflowPatch> GenerateAsync(
            ParsedWorkflow workflow,
            IReadOnlyList<WorkflowFinding> findings,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException(
                "Patch generation should not execute.");
    }
}
