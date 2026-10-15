namespace DevSecOpsSentinel.Domain;

/// <summary>
/// One finding and what the proposed patch did about it.
///
/// Carries the finding's own line and description rather than only its rule id. Without
/// them a consumer that needed either had to pair this list back against
/// <see cref="RemediationReport.OriginalAnalysis"/> positionally, which made an
/// implementation detail of how the list is built — a projection over the original findings,
/// in order — into a contract nothing enforced.
/// </summary>
public sealed record RemediationChange(
    string RuleId,
    string Title,
    WorkflowSeverity Severity,
    int? LineNumber,
    string Description,
    string Recommendation,
    bool Resolved);

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
