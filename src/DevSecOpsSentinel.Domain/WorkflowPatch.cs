namespace DevSecOpsSentinel.Domain;

public sealed record WorkflowPatch(
    string OriginalContent,
    string ProposedContent,
    IReadOnlyList<string> AppliedRuleIds,
    bool ProposedContentIsValid)
{
    public IReadOnlyList<string> ReferenceResolutionWarnings { get; init; } = [];
}
