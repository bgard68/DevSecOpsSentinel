namespace DevSecOpsSentinel.Api;

/// <summary>
/// A request carrying a workflow to analyse.
///
/// Declared so one endpoint filter can validate every such request. The checks used to be
/// repeated in each handler, which meant the 100,000-character limit was a thing the author
/// of the next endpoint had to remember — and the explain endpoint had to build a throwaway
/// <see cref="AnalyzeWorkflowRequest"/> just to reuse the validation.
/// </summary>
public interface IWorkflowRequest
{
    string FileName { get; }
    string Content { get; }
}

public sealed record AnalyzeWorkflowRequest(string FileName, string Content)
    : IWorkflowRequest;

public sealed record ExplainWorkflowRequest(
    string FileName,
    string Content,
    bool UseAi = true) : IWorkflowRequest;

public sealed record AnalyzeGitHubWorkflowRequest(
    string Path,
    string? Reference,
    bool UseAi = false);
