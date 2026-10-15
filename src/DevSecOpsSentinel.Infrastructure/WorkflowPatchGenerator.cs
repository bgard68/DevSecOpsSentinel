using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;
using DevSecOpsSentinel.Infrastructure.GitHub;
using DevSecOpsSentinel.Infrastructure.Rules.Fixes;

namespace DevSecOpsSentinel.Infrastructure;

/// <summary>
/// Applies the fixes the rules propose, then refuses the result unless it is provably no
/// worse than what it replaced.
///
/// This class used to hold the repairs themselves, selected by comparing each finding's rule
/// id against string literals. That made it the one place every fixable rule had to be
/// edited, gave it knowledge of three rules' YAML shapes, and coupled it to their identity
/// by a string the compiler could not check. The repairs now live with their rules as
/// <see cref="IWorkflowFix"/> implementations, and what remains here is the part that is
/// genuinely shared: line arithmetic, and the validation guarantee.
/// </summary>
public sealed class WorkflowPatchGenerator(
    IWorkflowParser parser,
    IEnumerable<IWorkflowSecurityRule> rules,
    IEnumerable<IWorkflowFix> fixes)
    : IWorkflowPatchGenerator
{
    private readonly IReadOnlyList<IWorkflowSecurityRule> _rules = rules.ToArray();
    private readonly IReadOnlyList<IWorkflowFix> _fixes = fixes.ToArray();

    /// <summary>
    /// The default fix set, for callers that compose this by hand rather than through the
    /// container.
    /// </summary>
    public WorkflowPatchGenerator(
        IWorkflowParser parser,
        IEnumerable<IWorkflowSecurityRule> rules,
        IWorkflowActionReferenceResolver actionReferenceResolver,
        GitHubOptions gitHubOptions)
        : this(
            parser,
            rules,
            FixDiscovery.All(actionReferenceResolver, gitHubOptions))
    {
    }

    public async Task<WorkflowPatch> GenerateAsync(
        ParsedWorkflow workflow,
        IReadOnlyList<WorkflowFinding> findings,
        CancellationToken cancellationToken)
    {
        List<string> lines = workflow.Document.Content
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n')
            .Split('\n')
            .ToList();

        HashSet<int> semanticLineNumbers = workflow.Lines
            .Select(line => line.Number)
            .ToHashSet();

        // Every fix reads the document as it was reported on, and the engine edits it
        // afterwards. A fix therefore cannot be handed a line some other fix has already
        // rewritten, which is what makes the line number on a finding mean the same thing to
        // every fix that sees it.
        WorkflowFixContext context = new(workflow, lines);

        List<WorkflowFinding> appliedFindings = [];
        List<string> resolutionWarnings = [];
        List<WorkflowLineEdit> edits = [];

        foreach (WorkflowFinding finding in findings
            .Where(finding => finding.IsAutomaticallyFixable))
        {
            // Established once, here, so no fix has to re-check that the line it was given
            // exists and is one the parser considers semantic — the guard that keeps a patch
            // out of the body of a shell script.
            if (!CanPatchLine(
                finding.LineNumber,
                lines.Count,
                semanticLineNumbers))
            {
                continue;
            }

            foreach (IWorkflowFix fix in _fixes
                .Where(fix => string.Equals(
                    fix.RuleId,
                    finding.RuleId,
                    StringComparison.Ordinal)))
            {
                WorkflowFixResult result = await fix.ProposeAsync(
                    context,
                    finding,
                    cancellationToken);

                resolutionWarnings.AddRange(result.Warnings);

                if (result.IsApplied)
                {
                    edits.AddRange(result.Edits);
                    appliedFindings.Add(finding);
                }
            }
        }

        ApplyEdits(lines, edits);

        string proposed = string.Join('\n', lines);
        WorkflowDocument proposedDocument = new(
            workflow.Document.FileName,
            proposed);

        bool proposedContentIsValid = ValidateProposedContent(
            workflow,
            findings,
            appliedFindings,
            proposedDocument);

        return new WorkflowPatch(
            workflow.Document.Content,
            proposed,
            appliedFindings
                .Select(finding => finding.RuleId)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(id => id, StringComparer.Ordinal)
                .ToArray(),
            proposedContentIsValid)
        {
            ReferenceResolutionWarnings = resolutionWarnings,

            // Which findings were edited, not just which rules. The generator is the only
            // component that knows this; flattening it to rule ids here forced everything
            // downstream to guess.
            AppliedFindings = appliedFindings
        };
    }

    /// <summary>
    /// Replacements first, then insertions from the bottom of the file upwards.
    ///
    /// Insertions move every line beneath them, so applying them in descending line order is
    /// what lets a fix state a position against the original document and ignore the
    /// existence of the others. The generator previously achieved this by running the one
    /// inserting rule in a separate pass, which only worked while exactly one rule inserted.
    /// </summary>
    private static void ApplyEdits(
        List<string> lines,
        IReadOnlyList<WorkflowLineEdit> edits)
    {
        foreach (WorkflowLineEdit edit in edits
            .Where(edit => edit.Kind == WorkflowEditKind.Replace))
        {
            lines[edit.LineNumber - 1] = edit.Text;
        }

        foreach (WorkflowLineEdit edit in edits
            .Where(edit => edit.Kind == WorkflowEditKind.InsertAfter)
            .OrderByDescending(edit => edit.LineNumber))
        {
            lines.Insert(edit.LineNumber, edit.Text);
        }
    }

    private bool ValidateProposedContent(
        ParsedWorkflow originalWorkflow,
        IReadOnlyList<WorkflowFinding> originalFindings,
        IReadOnlyList<WorkflowFinding> appliedFindings,
        WorkflowDocument proposedDocument)
    {
        WorkflowParseResult parseResult = parser.Parse(proposedDocument);

        if (!parseResult.IsValid ||
            parseResult.Workflow is not ParsedWorkflow proposedWorkflow)
        {
            return false;
        }

        if (!HasEquivalentStructure(
            originalWorkflow,
            proposedWorkflow))
        {
            return false;
        }

        WorkflowFinding[] proposedFindings = _rules
            .SelectMany(rule => rule.Evaluate(proposedWorkflow))
            .ToArray();

        IReadOnlyDictionary<string, int> originalCounts =
            CountByRule(originalFindings);

        IReadOnlyDictionary<string, int> appliedCounts =
            CountByRule(appliedFindings);

        IReadOnlyDictionary<string, int> proposedCounts =
            CountByRule(proposedFindings);

        HashSet<string> allRuleIds = originalCounts.Keys
            .Concat(proposedCounts.Keys)
            .ToHashSet(StringComparer.Ordinal);

        foreach (string ruleId in allRuleIds)
        {
            int originalCount =
                originalCounts.GetValueOrDefault(ruleId);
            int appliedCount =
                appliedCounts.GetValueOrDefault(ruleId);
            int proposedCount =
                proposedCounts.GetValueOrDefault(ruleId);

            int maximumExpectedCount =
                Math.Max(0, originalCount - appliedCount);

            if (proposedCount > maximumExpectedCount)
            {
                return false;
            }
        }

        return true;
    }

    private static bool HasEquivalentStructure(
        ParsedWorkflow original,
        ParsedWorkflow proposed)
    {
        // Job counts come from the parsed structure, the same source the rules
        // read, so patch validation and detection cannot disagree about what a
        // job is.
        return original.Structure.Jobs.Count == proposed.Structure.Jobs.Count &&
            original.Triggers
                .OrderBy(trigger => trigger, StringComparer.Ordinal)
                .SequenceEqual(
                    proposed.Triggers.OrderBy(
                        trigger => trigger,
                        StringComparer.Ordinal),
                    StringComparer.Ordinal);
    }

    private static IReadOnlyDictionary<string, int> CountByRule(
        IEnumerable<WorkflowFinding> findings) =>
        findings
            .GroupBy(
                finding => finding.RuleId,
                StringComparer.Ordinal)
            .ToDictionary(
                group => group.Key,
                group => group.Count(),
                StringComparer.Ordinal);

    private static bool CanPatchLine(
        int? lineNumber,
        int lineCount,
        IReadOnlySet<int> semanticLineNumbers)
    {
        return lineNumber is >= 1 &&
            lineNumber <= lineCount &&
            semanticLineNumbers.Contains(lineNumber.Value);
    }
}
