namespace DevSecOpsSentinel.Domain;

public sealed record WorkflowAnalysisResult(
    string FileName,
    bool IsValid,
    IReadOnlyList<string> ValidationErrors,
    IReadOnlyList<WorkflowFinding> Findings,
    WorkflowPatch? Patch)
{
    public int FindingCount => Findings.Count;

    /// <summary>
    /// Grants and configurations a rule examined and accepted, with the reason.
    /// Deliberately separate from <see cref="Findings"/> so accepting something
    /// never inflates the finding count or the risk level.
    /// </summary>
    public IReadOnlyList<WorkflowAcknowledgement> Acknowledgements { get; init; } = [];
}
