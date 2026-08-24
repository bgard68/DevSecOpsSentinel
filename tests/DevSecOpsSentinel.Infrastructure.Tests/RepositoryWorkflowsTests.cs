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
    /// Not a way to quieten the scanner. Each entry is a write grant that is the
    /// documented minimum for its job and cannot be removed without breaking it,
    /// and the count is exact - a second finding in the same file still fails.
    /// The test also fails if an accepted finding stops appearing, so an entry
    /// that outlives its reason has to be deleted rather than quietly kept.
    /// </summary>
    private static readonly Dictionary<string, (string RuleId, int Count, string Why)[]> Accepted =
        new()
        {
            ["codeql.yml"] =
            [
                ("GHA002", 1,
                    "security-events: write is the minimum for uploading analysis results.")
            ],
            ["dependency-review.yml"] =
            [
                ("GHA002", 1,
                    "pull-requests: write is the minimum for posting the review summary.")
            ],
            ["prune-runs.yml"] =
            [
                ("GHA002", 1,
                    "actions: write is the minimum for deleting a workflow run, and there is "
                    + "no narrower grant. Accepted with the cost stated: it also permits "
                    + "deleting any run in the repository, so this job can destroy the audit "
                    + "trail it exists to keep readable. Held to one job in one workflow that "
                    + "checks out nothing and reads no secret.")
            ]
        };

    private static string WorkflowDirectory()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            string candidate = Path.Combine(directory.FullName, ".github", "workflows");
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
        string path = Path.Combine(WorkflowDirectory(), fileName);
        WorkflowParseResult result = _parser.Parse(
            new WorkflowDocument(fileName, File.ReadAllText(path)));

        Assert.True(
            result.IsValid,
            $"{fileName} did not parse: {string.Join("; ", result.Errors)}");
        ParsedWorkflow workflow = Assert.IsType<ParsedWorkflow>(result.Workflow);

        List<WorkflowFinding> findings =
            [.. AllRules().SelectMany(rule => rule.Evaluate(workflow))];

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
