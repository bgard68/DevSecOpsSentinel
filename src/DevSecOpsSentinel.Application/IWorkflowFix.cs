using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Application;

/// <summary>
/// The remediation half of a rule: how a finding this rule reported is repaired.
///
/// Detection was already polymorphic — <see cref="IWorkflowSecurityRule"/>, one class per
/// rule, discovered rather than listed. Repair was not. It lived in the patch generator as a
/// chain of comparisons against rule id literals, so a single class held GHA001's action
/// reference regex, GHA002's exact permission text and GHA003's indentation convention,
/// while the rules that define those things sat in another folder knowing nothing about it.
///
/// That split the knowledge of one rule across two classes and made the catalogue's own
/// claim — that a rule is a new class and one registration line — false for any rule that
/// can be fixed, because the generator had to be edited too. Worse, the coupling was by
/// string: renaming a rule id compiled cleanly and silently stopped repairing anything.
///
/// A fix proposes edits rather than performing them. Line arithmetic is the engine's
/// problem, which is what removed the generator's second pass — a loop that existed only to
/// visit GHA003 in descending line order so its insertions would not invalidate the line
/// numbers of the findings behind it.
/// </summary>
public interface IWorkflowFix
{
    /// <summary>
    /// The rule whose findings this fix repairs. Matched against
    /// <see cref="WorkflowFinding.RuleId"/>.
    /// </summary>
    string RuleId { get; }

    /// <summary>
    /// Edits that would resolve <paramref name="finding"/>, or
    /// <see cref="WorkflowFixResult.NotApplicable"/> when it cannot be repaired.
    ///
    /// Declining is a normal outcome, not a failure: an action reference that cannot be
    /// resolved to a commit SHA is deliberately left alone rather than rewritten with
    /// something that would look remediated. A fix that declines with a warning says why.
    /// </summary>
    Task<WorkflowFixResult> ProposeAsync(
        WorkflowFixContext context,
        WorkflowFinding finding,
        CancellationToken cancellationToken);
}

/// <summary>
/// What a fix may read. Lines are the document as the patch engine currently holds it,
/// indexed from one to match <see cref="WorkflowFinding.LineNumber"/> — the engine has
/// already established that the finding's line exists and is one the parser considers
/// semantic, so a fix does not re-check either.
/// </summary>
public sealed record WorkflowFixContext(
    ParsedWorkflow Workflow,
    IReadOnlyList<string> Lines)
{
    public string Line(int lineNumber) => Lines[lineNumber - 1];
}

/// <summary>
/// A single line-level change. Kept to replacement and insertion because those are what the
/// patch engine can apply and still guarantee the line numbers every other finding was
/// reported against remain meaningful.
/// </summary>
public enum WorkflowEditKind
{
    /// <summary>Replace the line's entire text.</summary>
    Replace,

    /// <summary>Insert a new line immediately below it.</summary>
    InsertAfter
}

public sealed record WorkflowLineEdit(
    WorkflowEditKind Kind,
    int LineNumber,
    string Text)
{
    public static WorkflowLineEdit Replace(int lineNumber, string text) =>
        new(WorkflowEditKind.Replace, lineNumber, text);

    public static WorkflowLineEdit InsertAfter(int lineNumber, string text) =>
        new(WorkflowEditKind.InsertAfter, lineNumber, text);
}

/// <summary>
/// The outcome of asking a fix to repair one finding.
///
/// A result carrying no edits leaves the finding unresolved, whether or not it carries a
/// warning. Only a result with edits counts as applied, so a fix cannot reduce the reported
/// risk without having changed something.
/// </summary>
public sealed record WorkflowFixResult(
    IReadOnlyList<WorkflowLineEdit> Edits,
    IReadOnlyList<string> Warnings)
{
    /// <summary>
    /// Nothing to do and nothing to say — the finding's line does not have the shape this
    /// fix repairs. Silent on purpose: it is not a failure the reader can act on.
    /// </summary>
    public static readonly WorkflowFixResult NotApplicable = new([], []);

    public bool IsApplied => Edits.Count > 0;

    /// <summary>Declined, with the reason surfaced to the reader.</summary>
    public static WorkflowFixResult Declined(string warning) => new([], [warning]);

    public static WorkflowFixResult Applied(params WorkflowLineEdit[] edits) => new(edits, []);
}
