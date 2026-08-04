namespace DevSecOpsSentinel.Api;

public sealed record AnalyzeWorkflowRequest(string FileName, string Content);

public sealed record ExplainWorkflowRequest(
    string FileName,
    string Content,
    bool UseAi = true);

public sealed record AnalyzeGitHubWorkflowRequest(
    string Path,
    string? Reference,
    bool UseAi = false);
