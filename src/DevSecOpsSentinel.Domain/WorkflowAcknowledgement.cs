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
    int? LineNumber);
