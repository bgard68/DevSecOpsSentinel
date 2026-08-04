namespace DevSecOpsSentinel.Domain;

public sealed record AiFindingExplanation(
    string RuleId,
    string WhyItMatters,
    string RecommendedAction,
    string Confidence);

public sealed record WorkflowAiExplanation(
    string Summary,
    IReadOnlyList<AiFindingExplanation> Findings,
    string RecommendedNextStep,
    IReadOnlyList<string> Limitations,
    bool GeneratedByAi,
    string Mode,
    string? FallbackReason = null);

public sealed record WorkflowExplanationResult(
    WorkflowAnalysisResult Analysis,
    WorkflowAiExplanation Explanation,
    bool SensitiveContentRedacted);
