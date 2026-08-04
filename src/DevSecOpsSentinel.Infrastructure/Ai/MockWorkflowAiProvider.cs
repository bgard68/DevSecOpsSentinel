using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Ai;

public sealed class MockWorkflowAiProvider : IWorkflowAiProvider
{
    public Task<WorkflowAiExplanation> ExplainAsync(
        WorkflowAnalysisResult analysis,
        string sanitizedContent,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        AiFindingExplanation[] findings = analysis.Findings.Select(finding =>
            new AiFindingExplanation(
                finding.RuleId,
                $"{finding.Description} This explanation is produced by the cost-free mock provider.",
                finding.Recommendation,
                "high"))
            .ToArray();

        WorkflowAiExplanation explanation = new(
            analysis.Findings.Count == 0
                ? "No configured rule violations were detected. Continue normal review and testing."
                : $"The workflow contains {analysis.Findings.Count} deterministic security finding(s) that should be reviewed.",
            findings,
            "Review the proposed patch, run the workflow in a sandbox, and require human approval before merging.",
            [
                "Mock mode does not contact OpenAI or consume API credits.",
                "The deterministic rule engine remains the source of truth."
            ],
            false,
            "Mock");

        return Task.FromResult(explanation);
    }
}
