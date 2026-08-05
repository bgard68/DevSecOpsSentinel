using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Application;

public sealed class WorkflowExplanationService(
    IWorkflowAnalysisService analysisService,
    IWorkflowAiProviderSelector providerSelector,
    ISensitiveDataSanitizer sanitizer) : IWorkflowExplanationService
{
    public async Task<WorkflowExplanationResult> ExplainAsync(
        WorkflowDocument document,
        bool useAi,
        AiCallerAccess access,
        CancellationToken cancellationToken)
    {
        WorkflowAnalysisResult analysis =
            await analysisService.AnalyzeAsync(
                document,
                cancellationToken);
        SanitizedWorkflow sanitized = sanitizer.Sanitize(document.Content);

        WorkflowAiExplanation explanation;
        if (!analysis.IsValid)
        {
            explanation = AiExplanationFactory.CreateFallback(
                analysis,
                "Deterministic",
                "AI explanation was skipped because the workflow YAML is invalid.");
        }
        else if (!useAi)
        {
            explanation = AiExplanationFactory.CreateFallback(
                analysis,
                "Disabled",
                "AI explanation was not requested.");
        }
        else
        {
            explanation = await providerSelector
                .Select(access)
                .ExplainAsync(
                    analysis,
                    sanitized.Content,
                    cancellationToken);
        }

        return new WorkflowExplanationResult(analysis, explanation, sanitized.WasRedacted);
    }
}

public static class AiExplanationFactory
{
    public static WorkflowAiExplanation CreateFallback(
        WorkflowAnalysisResult analysis,
        string mode,
        string reason)
    {
        AiFindingExplanation[] findings = analysis.Findings
            .Select(finding => new AiFindingExplanation(
                finding.RuleId,
                finding.Description,
                finding.Recommendation,
                "deterministic"))
            .ToArray();

        string summary = analysis.Findings.Count == 0
            ? "The deterministic scanner did not identify any configured rule violations."
            : $"The deterministic scanner identified {analysis.Findings.Count} finding(s).";

        return new WorkflowAiExplanation(
            summary,
            findings,
            "Review the deterministic findings and validate any proposed patch before applying it.",
            ["This fallback was generated without a live OpenAI request."],
            false,
            mode,
            reason);
    }
}
