namespace DevSecOpsSentinel.Domain;

public sealed record WorkflowAnalysisResult(
    string FileName,
    bool IsValid,
    IReadOnlyList<string> ValidationErrors,
    IReadOnlyList<WorkflowFinding> Findings,
    WorkflowPatch? Patch)
{
    public int FindingCount => Findings.Count;
}
