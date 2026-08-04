namespace DevSecOpsSentinel.Domain;

public sealed record RemediationChange(
    string RuleId,
    string Title,
    WorkflowSeverity Severity,
    bool Resolved,
    string Recommendation);

public sealed record RemediationReport(
    string FileName,
    WorkflowAnalysisResult OriginalAnalysis,
    WorkflowAnalysisResult ProposedAnalysis,
    IReadOnlyList<RemediationChange> Changes,
    IReadOnlyList<string> UnifiedDiff,
    int OriginalRiskScore,
    int ProposedRiskScore,
    int RiskReductionPercent,
    bool PatchValid)
{
    public int ResolvedFindingCount => Changes.Count(change => change.Resolved);
    public int RemainingFindingCount => ProposedAnalysis.Findings.Count;
}
