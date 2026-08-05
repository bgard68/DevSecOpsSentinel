using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Application;

public interface IWorkflowExplanationService
{
    Task<WorkflowExplanationResult> ExplainAsync(
        WorkflowDocument document,
        bool useAi,
        AiCallerAccess access,
        CancellationToken cancellationToken);
}

public interface IWorkflowAiProvider
{
    Task<WorkflowAiExplanation> ExplainAsync(
        WorkflowAnalysisResult analysis,
        string sanitizedContent,
        CancellationToken cancellationToken);
}

/// <summary>
/// What the caller of an explanation is entitled to ask the model for.
///
/// Passed explicitly rather than read from ambient request state, so the
/// decision is visible at the call site and can be exercised in a test without
/// constructing an HTTP context.
/// </summary>
public enum AiCallerAccess
{
    /// <summary>
    /// Mock regardless of how the server is configured. An unidentified caller
    /// cannot cause an outbound request, so cannot spend anything.
    /// </summary>
    MockOnly,

    /// <summary>Whatever the server is configured for, Live included.</summary>
    Configured
}

/// <summary>
/// Chooses the provider for one request. Replaces selecting a single provider
/// at startup, which could not vary by caller.
/// </summary>
public interface IWorkflowAiProviderSelector
{
    IWorkflowAiProvider Select(AiCallerAccess access);
}

public interface ISensitiveDataSanitizer
{
    SanitizedWorkflow Sanitize(string content);
}

public sealed record SanitizedWorkflow(string Content, bool WasRedacted);
