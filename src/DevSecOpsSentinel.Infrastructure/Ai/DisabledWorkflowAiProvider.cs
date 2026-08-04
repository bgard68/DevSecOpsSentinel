using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Ai;

public sealed class DisabledWorkflowAiProvider : IWorkflowAiProvider
{
    public Task<WorkflowAiExplanation> ExplainAsync(
        WorkflowAnalysisResult analysis,
        string sanitizedContent,
        CancellationToken cancellationToken) =>
        Task.FromResult(AiExplanationFactory.CreateFallback(
            analysis,
            "Disabled",
            "OpenAI integration is disabled by configuration."));
}
