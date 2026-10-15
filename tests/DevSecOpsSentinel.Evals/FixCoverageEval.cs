using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;
using DevSecOpsSentinel.Infrastructure;
using DevSecOpsSentinel.Infrastructure.GitHub;
using DevSecOpsSentinel.Infrastructure.Rules;
using DevSecOpsSentinel.Infrastructure.Rules.Fixes;

namespace DevSecOpsSentinel.Evals;

/// <summary>
/// Holds <see cref="FixDiscovery"/> to the rules.
///
/// Rules are discovered by reflection; fixes cannot be, because a fix takes constructor
/// arguments and activating one without them would skip exactly the fixes that have
/// dependencies. So the fix list is written by hand, and a hand-written list drifts.
///
/// Both directions are checked, because they fail differently. A rule that marks its
/// findings automatically fixable with no fix registered offers the user a remediation
/// preview that silently changes nothing. A fix naming a rule id that no rule reports is
/// dead code that will never run — which is what a rule id rename produces, since the
/// coupling is a string the compiler cannot check.
///
/// This leans on <see cref="CorpusEval.Corpus_RegisteredRules_AreAllExercised"/>: every
/// registered rule fires somewhere in the corpus, so findings gathered across the whole
/// corpus are a complete sample of what the rules can report.
/// </summary>
public sealed class FixCoverageEval
{
    private static readonly WorkflowParser Parser = new();
    private static readonly IReadOnlyList<IWorkflowSecurityRule> AllRules = RuleDiscovery.All();

    /// <summary>
    /// The resolver is never called — only <see cref="IWorkflowFix.RuleId"/> is read — but
    /// constructing the list requires one.
    /// </summary>
    private static readonly IReadOnlyList<IWorkflowFix> AllFixes =
        FixDiscovery.All(new UnusedResolver(), new GitHubOptions());

    [Fact]
    public void EveryAutomaticallyFixableRule_HasAFixRegistered()
    {
        string[] fixable = [.. GoldenCorpus.Entries
            .SelectMany(entry => FindingsIn(entry.FileName))
            .Where(finding => finding.IsAutomaticallyFixable)
            .Select(finding => finding.RuleId)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)];

        string[] unfixed = [.. fixable
            .Except(AllFixes.Select(fix => fix.RuleId), StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)];

        Assert.True(
            unfixed.Length == 0,
            $"Rules reporting automatically fixable findings with no IWorkflowFix registered "
            + $"in FixDiscovery: {Join(unfixed)}. The remediation preview would report these "
            + "as fixable and then change nothing.");
    }

    [Fact]
    public void EveryRegisteredFix_NamesARuleThatExists()
    {
        string[] orphaned = [.. AllFixes
            .Select(fix => fix.RuleId)
            .Except(AllRules.Select(rule => rule.RuleId), StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)];

        Assert.True(
            orphaned.Length == 0,
            $"Fixes registered against rule ids no rule reports: {Join(orphaned)}. "
            + "A fix matched to nothing never runs, and nothing else reports that.");
    }

    [Fact]
    public void RegisteredFixes_DoNotCompeteForTheSameRule()
    {
        // Two fixes for one rule both get asked, and both sets of edits are applied. That may
        // be intended one day; it is not today, and finding out by watching two fixes rewrite
        // the same line is the expensive way to learn it.
        string[] duplicated = [.. AllFixes
            .GroupBy(fix => fix.RuleId, StringComparer.Ordinal)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)
            .Order(StringComparer.Ordinal)];

        Assert.True(
            duplicated.Length == 0,
            $"More than one fix registered for: {Join(duplicated)}.");
    }

    private static IReadOnlyList<WorkflowFinding> FindingsIn(string fileName)
    {
        string content = File.ReadAllText(Path.Join(CorpusEval.CorpusDirectory, fileName));
        WorkflowParseResult parsed = Parser.Parse(new WorkflowDocument(fileName, content));

        Assert.True(
            parsed is { IsValid: true, Workflow: not null },
            $"{fileName} did not parse: {string.Join("; ", parsed.Errors)}");

        return [.. AllRules.SelectMany(rule => rule.Evaluate(parsed.Workflow!))];
    }

    private static string Join(IEnumerable<string> ids)
    {
        string joined = string.Join(", ", ids);
        return joined.Length == 0 ? "(none)" : joined;
    }

    private sealed class UnusedResolver : IWorkflowActionReferenceResolver
    {
        public Task<ActionReferenceResolutionResult> ResolveAsync(
            string actionReference,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException(
                "This eval reads rule ids only and must not resolve an action reference.");
    }
}
