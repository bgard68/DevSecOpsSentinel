namespace DevSecOpsSentinel.Domain;

/// <summary>
/// Something a rule examined and deliberately did not report.
///
/// Not a finding, and kept out of <see cref="WorkflowAnalysisResult.Findings"/>
/// on purpose: the client reads a non-zero finding count as "Action required",
/// so carrying these as findings would turn a correct workflow into one that
/// appears to need work — the opposite of what establishing need was for.
///
/// It exists because silence is ambiguous. When GHA002 stopped reporting the
/// write grant CodeQL cannot work without, nothing distinguished "the rule
/// checked this and accepted it" from "the rule never looked", and the
/// reasoning that made the finding disappear was invisible to the person
/// deciding whether to trust the result.
/// </summary>
public sealed record WorkflowAcknowledgement(
    string RuleId,
    string Title,
    string Detail,
    int? LineNumber,
    WorkflowAcceptedBy AcceptedBy = WorkflowAcceptedBy.Rule);

/// <summary>
/// Who decided a finding was acceptable. The two carry different weight and a
/// reader has to be able to tell them apart: one is a fact about what an action
/// requires, the other is a person's judgement, and only the second can be
/// wrong about the risk.
/// </summary>
public enum WorkflowAcceptedBy
{
    /// <summary>Established by the rule - the grant is a documented requirement.</summary>
    Rule = 0,

    /// <summary>Accepted in the workflow by its author, with a stated reason.</summary>
    Author = 1
}
