using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;
using DevSecOpsSentinel.Infrastructure;
using DevSecOpsSentinel.Infrastructure.Rules;

namespace DevSecOpsSentinel.Infrastructure.Tests;

/// <summary>
/// This repository's own workflows, measured against this repository's own
/// rules.
///
/// A scanner whose own pipeline would fail its analysis is making a claim it
/// does not keep. Every other test here feeds the rules a fixture written to
/// provoke them; this one feeds them the real thing, which is the only input
/// that can regress without anyone editing a test.
/// </summary>
public sealed class RepositoryWorkflowsTests
{
    private readonly WorkflowParser _parser = new();

    private static IReadOnlyList<IWorkflowSecurityRule> AllRules() =>
        RuleCatalogue.All();

    /// <summary>
    /// Findings this repository has read and accepted, with the reason.
    ///
    /// Empty, and that is the point. Every entry that used to live here now
    /// lives in the workflow it is about: codeql.yml's and
    /// dependency-review.yml's grants are recognised by the rule itself, and
    /// prune-runs.yml states its own acceptance in a sentinel:accept comment
    /// beside the grant. A reason kept in a test file is invisible to anyone
    /// reading the workflow, and outlives the code it was written about without
    /// anything noticing.
    ///
    /// The mechanism is still enforced: an acceptance with no reason is refused,
    /// and one that stops matching a finding is reported.
    /// </summary>
    private static readonly Dictionary<string, (string RuleId, int Count, string Why)[]> Accepted =
        new();

    private static string WorkflowDirectory()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            string candidate = Path.Join(directory.FullName, ".github", "workflows");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException(
            $"No .github/workflows directory above {AppContext.BaseDirectory}.");
    }

    public static TheoryData<string> WorkflowFiles()
    {
        TheoryData<string> data = [];
        foreach (string path in Directory.EnumerateFiles(WorkflowDirectory(), "*.yml"))
        {
            data.Add(Path.GetFileName(path));
        }

        return data;
    }

    [Fact]
    public void There_are_workflows_to_check()
    {
        // Without this, a wrong directory would make every case below pass by
        // having nothing to examine - the failure mode the repository-validation
        // gate was rewritten to close.
        Assert.NotEmpty(WorkflowFiles());
    }

    [Theory]
    [MemberData(nameof(WorkflowFiles))]
    public void Our_own_workflows_pass_our_own_rules(string fileName)
    {
        string path = Path.Join(WorkflowDirectory(), fileName);
        WorkflowParseResult result = _parser.Parse(
            new WorkflowDocument(fileName, File.ReadAllText(path)));

        Assert.True(
            result.IsValid,
            $"{fileName} did not parse: {string.Join("; ", result.Errors)}");
        ParsedWorkflow workflow = Assert.IsType<ParsedWorkflow>(result.Workflow);

        // Measured the way the product reports, not the way the rules fire: an
        // acceptance stated in the workflow is part of the analysis, and a test
        // that skipped it would hold this repository to a stricter standard than
        // the tool applies to anyone else's.
        List<WorkflowFinding> raw =
            [.. AllRules().SelectMany(rule => rule.Evaluate(workflow))];

        WorkflowSuppressions suppressions = WorkflowSuppressions.Read(workflow);
        List<WorkflowFinding> findings =
            [.. raw.Where(finding => suppressions.For(finding) is null)];

        // An acceptance that no longer matches anything, or that states no
        // reason, is a defect in its own right - the same standard the analyser
        // holds every other repository to.
        Assert.True(
            suppressions.Stale(raw).Count == 0,
            $"{fileName} accepts findings that are no longer reported: "
                + string.Join(", ", suppressions.Stale(raw).Select(e => $"{e.RuleId} line {e.DirectiveLine}")));

        Assert.True(
            suppressions.WithoutReason.Count == 0,
            $"{fileName} has sentinel:accept comments with no reason on lines: "
                + string.Join(", ", suppressions.WithoutReason));

        (string RuleId, int Count, string Why)[] accepted =
            Accepted.TryGetValue(fileName, out (string, int, string)[]? entries)
                ? entries
                : [];

        List<string> unexpected = [];
        foreach (IGrouping<string, WorkflowFinding> group in
            findings.GroupBy(finding => finding.RuleId))
        {
            int allowance = accepted
                .Where(entry => entry.RuleId == group.Key)
                .Sum(entry => entry.Count);

            foreach (WorkflowFinding finding in group.Skip(allowance))
            {
                unexpected.Add(
                    $"{finding.RuleId} [{finding.Severity}] line {finding.LineNumber}: {finding.Title}");
            }
        }

        Assert.True(
            unexpected.Count == 0,
            $"{fileName} would be reported by this project's own rules:\n  "
                + string.Join("\n  ", unexpected));

        // An exception that no longer corresponds to a real finding is worse
        // than no exception: it reads as considered when nothing considered it.
        foreach ((string ruleId, int count, string why) in accepted)
        {
            Assert.True(
                findings.Count(finding => finding.RuleId == ruleId) == count,
                $"{fileName} no longer produces {count} {ruleId} finding(s). "
                    + $"Remove the accepted entry: {why}");
        }
    }
}
