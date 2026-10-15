using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Rules.Fixes;

/// <summary>
/// Repairs GHA003 by declaring a timeout on the job that lacks one.
///
/// The only fix that inserts rather than replaces, which used to make it a special case in
/// the patch generator: an insertion shifts every line below it, so the generator ran GHA003
/// in a second pass ordered by descending line number. The engine now orders insertions, so
/// this states where the line goes and nothing more.
///
/// Fifteen minutes is a default, not a recommendation — the rule's own wording asks for a
/// value appropriate to the job. It is deliberately short enough to be noticed and edited.
/// See <see cref="MissingTimeoutRule"/> for detection, including why a job that calls a
/// reusable workflow is never reported here.
/// </summary>
public sealed class MissingTimeoutFix : IWorkflowFix
{
    private const int DefaultTimeoutMinutes = 15;

    public string RuleId => "GHA003";

    public Task<WorkflowFixResult> ProposeAsync(
        WorkflowFixContext context,
        WorkflowFinding finding,
        CancellationToken cancellationToken)
    {
        string declaration = context.Line(finding.LineNumber!.Value);
        int indent = declaration.Length - declaration.TrimStart().Length;

        return Task.FromResult(
            WorkflowFixResult.Applied(
                WorkflowLineEdit.InsertAfter(
                    finding.LineNumber.Value,
                    new string(' ', indent + 2) +
                        $"timeout-minutes: {DefaultTimeoutMinutes}")));
    }
}
