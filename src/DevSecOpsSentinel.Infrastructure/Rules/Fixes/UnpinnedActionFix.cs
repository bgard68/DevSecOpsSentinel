using System.Text.RegularExpressions;
using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;
using DevSecOpsSentinel.Infrastructure.GitHub;

namespace DevSecOpsSentinel.Infrastructure.Rules.Fixes;

/// <summary>
/// Repairs GHA001 by rewriting a movable action reference to the commit SHA it resolves to
/// today.
///
/// The one fix here that can fail, because it is the only one that has to ask GitHub
/// something. Every failure path leaves the line untouched and explains itself: a reference
/// rewritten with a placeholder would read as pinned while pinning nothing, which is worse
/// than the finding it replaced. See <see cref="UnpinnedActionRule"/> for detection.
/// </summary>
public sealed partial class UnpinnedActionFix(
    IWorkflowActionReferenceResolver resolver,
    GitHubOptions gitHubOptions) : IWorkflowFix
{
    public string RuleId => "GHA001";

    public async Task<WorkflowFixResult> ProposeAsync(
        WorkflowFixContext context,
        WorkflowFinding finding,
        CancellationToken cancellationToken)
    {
        // A finding that carries no line number gives a line edit nothing to target.
        if (finding.LineNumber is not int lineNumber)
        {
            return WorkflowFixResult.NotApplicable;
        }

        string line = context.Line(lineNumber);

        Match match = ActionReferenceRegex().Match(line);
        if (!match.Success)
        {
            return WorkflowFixResult.NotApplicable;
        }

        string actionReference = match.Groups["reference"].Value;

        if (!gitHubOptions.ResolveActionReferences)
        {
            return WorkflowFixResult.Declined(
                $"Line {lineNumber}: '{actionReference}' was not pinned because GitHub action reference resolution is disabled.");
        }

        ActionReferenceResolutionResult resolution =
            await resolver.ResolveAsync(actionReference, cancellationToken);

        if (!resolution.IsResolved || !IsFullCommitSha(resolution.CommitSha))
        {
            return WorkflowFixResult.Declined(
                $"Line {lineNumber}: {resolution.Message}");
        }

        Group version = match.Groups["version"];

        return WorkflowFixResult.Applied(
            WorkflowLineEdit.Replace(
                lineNumber,
                line[..version.Index] +
                    resolution.CommitSha +
                    line[(version.Index + version.Length)..]));
    }

    private static bool IsFullCommitSha(string? value) =>
        value is not null &&
        value.Length == 40 &&
        value.All(character =>
            character is >= '0' and <= '9' ||
            character is >= 'a' and <= 'f' ||
            character is >= 'A' and <= 'F');

    [GeneratedRegex(
        @"uses:\s*(?<reference>[^@\s#]+@(?<version>[^\s#]+))",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ActionReferenceRegex();
}
