using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;
using DevSecOpsSentinel.Infrastructure;
using DevSecOpsSentinel.Infrastructure.Rules;

namespace DevSecOpsSentinel.Evals;

/// <summary>
/// Scores the deterministic scanner against <see cref="GoldenCorpus"/>.
///
/// ADR-001 makes the rules the only source of truth, and ADR-003 makes the model's output
/// answerable to them. Everything downstream — the containment gate, the explanation, the
/// remediation preview — inherits whatever these rules get right or wrong. So the rules are
/// the thing worth measuring, and this is where the measurement lives.
///
/// Runs offline. No API key, no network, no spend, so it belongs on every push rather than
/// behind a decision about whether today is worth the credits.
/// </summary>
public sealed class CorpusEval
{
    private static readonly WorkflowParser Parser = new();

    /// <summary>
    /// The same discovery the composition root registers from, so the eval scores the rules
    /// the application actually runs rather than a second opinion about what they are.
    /// </summary>
    private static readonly IReadOnlyList<IWorkflowSecurityRule> AllRules = RuleDiscovery.All();

    public static TheoryData<string> CorpusFiles()
    {
        TheoryData<string> data = [];
        foreach (CorpusEntry entry in GoldenCorpus.Entries)
        {
            data.Add(entry.FileName);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(CorpusFiles))]
    public void Scanner_finds_exactly_what_the_corpus_expects(string fileName)
    {
        CorpusEntry entry = GoldenCorpus.Entries.Single(candidate => candidate.FileName == fileName);
        string[] actual = Scan(fileName);

        // Reported as two directed differences rather than a set comparison. "Missed" and
        // "spurious" are different defects — one is a scanner blind spot a user never sees,
        // the other is noise that trains a user to ignore the tool.
        string[] missed = [.. entry.ExpectedRuleIds.Except(actual, StringComparer.Ordinal).Order(StringComparer.Ordinal)];
        string[] spurious = [.. actual.Except(entry.ExpectedRuleIds, StringComparer.Ordinal).Order(StringComparer.Ordinal)];

        Assert.True(
            missed.Length == 0 && spurious.Length == 0,
            $"""
             {fileName} — {entry.Intent}
               expected : {Join(entry.ExpectedRuleIds)}
               actual   : {Join(actual)}
               missed   : {Join(missed)}
               spurious : {Join(spurious)}
             """);
    }

    [Fact]
    public void The_clean_baseline_produces_nothing()
    {
        // Called out separately from the theory because a false positive here is the one
        // failure that discredits the whole tool: if the workflow that does everything right
        // still gets flagged, no finding the scanner reports can be trusted.
        Assert.Empty(Scan("safe.yml"));
    }

    [Fact]
    public void Every_registered_rule_is_exercised_by_the_corpus()
    {
        string[] covered = [.. GoldenCorpus.Entries.SelectMany(entry => entry.ExpectedRuleIds).Distinct()];
        string[] uncovered = [.. AllRules.Select(rule => rule.RuleId)
            .Except(covered, StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)];

        Assert.True(
            uncovered.Length == 0,
            $"Rules registered in Infrastructure with no corpus fixture: {Join(uncovered)}. "
            + "Add a fixture that triggers each, or the rule ships unmeasured.");
    }

    [Fact]
    public void Corpus_entries_all_have_a_file_on_disk()
    {
        string[] missing = [.. GoldenCorpus.Entries
            .Select(entry => entry.FileName)
            .Where(name => !File.Exists(Path.Join(CorpusDirectory, name)))];

        Assert.True(missing.Length == 0, $"Declared but absent from Corpus/: {Join(missing)}");
    }

    [Fact]
    public void Corpus_files_on_disk_are_all_declared()
    {
        // The reverse direction. An undeclared .yml sitting in Corpus/ looks like coverage
        // in a directory listing while contributing nothing to the score.
        string[] declared = [.. GoldenCorpus.Entries.Select(entry => entry.FileName)];
        string[] undeclared = [.. Directory.EnumerateFiles(CorpusDirectory, "*.yml")
            .Select(Path.GetFileName)
            .OfType<string>()
            .Except(declared, StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)];

        Assert.True(undeclared.Length == 0, $"Present in Corpus/ but not in GoldenCorpus: {Join(undeclared)}");
    }

    [Fact]
    public void Write_scoreboard()
    {
        // Not an assertion — this emits the artifact CI publishes. Kept as a fact so it runs
        // in the ordinary test pass rather than needing a separate entry point.
        List<string> lines =
        [
            "# Scanner scoreboard",
            "",
            $"{GoldenCorpus.Entries.Count} fixtures, {AllRules.Count} registered rules.",
            "",
            "| Fixture | Expected | Actual | Result |",
            "|---|---|---|---|"
        ];

        foreach (CorpusEntry entry in GoldenCorpus.Entries)
        {
            string[] actual = Scan(entry.FileName);
            bool match = actual.OrderBy(id => id, StringComparer.Ordinal)
                .SequenceEqual(entry.ExpectedRuleIds.OrderBy(id => id, StringComparer.Ordinal), StringComparer.Ordinal);

            lines.Add($"| `{entry.FileName}` | {Join(entry.ExpectedRuleIds)} | {Join(actual)} | {(match ? "pass" : "**FAIL**")} |");
        }

        lines.AddRange(["", "| Rule | Fixtures |", "|---|---|"]);
        foreach (IWorkflowSecurityRule rule in AllRules)
        {
            int count = GoldenCorpus.Entries.Count(entry => entry.ExpectedRuleIds.Contains(rule.RuleId, StringComparer.Ordinal));
            lines.Add($"| {rule.RuleId} {rule.Title} | {(count == 0 ? "**none**" : count.ToString())} |");
        }

        string path = Path.Join(AppContext.BaseDirectory, "scoreboard.md");
        File.WriteAllLines(path, lines);
        Assert.True(File.Exists(path));
    }

    internal static string CorpusDirectory => Path.Join(AppContext.BaseDirectory, "Corpus");

    /// <summary>
    /// The scan a recorded reply is measured against. Shared with the replay eval so both
    /// score against identical scanner output rather than two descriptions of it.
    /// </summary>
    internal static WorkflowAnalysisResult AnalyzeForReplay(string fileName)
    {
        string content = File.ReadAllText(Path.Join(CorpusDirectory, fileName));
        WorkflowParseResult parsed = Parser.Parse(new WorkflowDocument(fileName, content));

        return new WorkflowAnalysisResult(
            fileName,
            IsValid: true,
            ValidationErrors: [],
            Findings: [.. AllRules.SelectMany(rule => rule.Evaluate(parsed.Workflow!))],
            Patch: null);
    }

    private static string[] Scan(string fileName)
    {
        string content = File.ReadAllText(Path.Join(CorpusDirectory, fileName));
        WorkflowParseResult parsed = Parser.Parse(new WorkflowDocument(fileName, content));

        Assert.True(
            parsed is { IsValid: true, Workflow: not null },
            $"{fileName} did not parse: {string.Join("; ", parsed.Errors)}");

        return [.. AllRules
            .SelectMany(rule => rule.Evaluate(parsed.Workflow!))
            .Select(finding => finding.RuleId)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)];
    }

    private static string Join(IEnumerable<string> ids)
    {
        string joined = string.Join(", ", ids);
        return joined.Length == 0 ? "(none)" : joined;
    }
}
