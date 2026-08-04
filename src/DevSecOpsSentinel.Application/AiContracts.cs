using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Application;

public interface IWorkflowExplanationService
{
    Task<WorkflowExplanationResult> ExplainAsync(
        WorkflowDocument document,
        bool useAi,
        CancellationToken cancellationToken);
}

public interface IWorkflowAiProvider
{
    Task<WorkflowAiExplanation> ExplainAsync(
        WorkflowAnalysisResult analysis,
        string sanitizedContent,
        CancellationToken cancellationToken);
}

public interface ISensitiveDataSanitizer
{
    SanitizedWorkflow Sanitize(string content);
}

public sealed record SanitizedWorkflow(string Content, bool WasRedacted);
