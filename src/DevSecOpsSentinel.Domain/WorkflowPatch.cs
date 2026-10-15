namespace DevSecOpsSentinel.Domain;

public sealed record WorkflowPatch(
    string OriginalContent,
    string ProposedContent,
    IReadOnlyList<string> AppliedRuleIds,
    bool ProposedContentIsValid)
{
    public IReadOnlyList<string> ReferenceResolutionWarnings { get; init; } = [];

    /// <summary>
    /// The individual findings this patch edited.
    ///
    /// <see cref="AppliedRuleIds"/> answers "which rules did this patch act on", which is
    /// the right question for a summary and the wrong one for attributing an outcome to a
    /// finding. Two unpinned actions are two findings under one rule id, and a patch that
    /// resolves one of them — because the other's reference could not be resolved to a
    /// commit SHA — is not described by that rule id either way.
    ///
    /// Reported per finding so a consumer never has to re-derive it, by index or by rule.
    /// </summary>
    public IReadOnlyList<WorkflowFinding> AppliedFindings { get; init; } = [];
}
