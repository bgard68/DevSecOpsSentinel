using System.Text.Json;
using DevSecOpsSentinel.Domain;
using DevSecOpsSentinel.Infrastructure.Ai;

namespace DevSecOpsSentinel.Evals;

/// <summary>
/// Replays recorded model replies through the containment gate and scores each against the
/// decision the gate should reach.
///
/// <see cref="AiContainmentTests"/> asks whether the gate works on payloads built in code.
/// This asks a different question: given replies in the shape a model actually returns —
/// including replies that do what an attacker asked — does the system reach the right answer?
/// Replies are data on disk, so a live capture can be added beside the authored ones and
/// scored by the same code.
///
/// Offline. The spend already happened, once, whenever a reply was captured.
/// </summary>
public sealed class ContainmentReplayEval
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static TheoryData<string> Replies()
    {
        TheoryData<string> data = [];
        foreach (ReplayEntry entry in ReplayCorpus.Entries)
        {
            data.Add(entry.ResponseFile);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Replies))]
    public void ContainmentGate_RecordedReply_ReachesTheExpectedVerdict(string responseFile)
    {
        ReplayEntry entry = ReplayCorpus.Entries.Single(candidate => candidate.ResponseFile == responseFile);

        WorkflowAnalysisResult analysis = CorpusEval.AnalyzeForReplay(entry.WorkflowFile);
        OpenAiWorkflowAiProvider.OpenAiExplanationPayload payload = Load(entry.ResponseFile);

        bool accepted = OpenAiWorkflowAiProvider.IsValid(payload, analysis);

        Assert.True(
            accepted == entry.ShouldBeAccepted,
            $"""
             {entry.ResponseFile} against {entry.WorkflowFile}
               expected : {(entry.ShouldBeAccepted ? "accepted" : "rejected")}
               actual   : {(accepted ? "accepted" : "rejected")}
               why      : {entry.Rationale}
             """);
    }

    [Theory]
    [MemberData(nameof(Replies))]
    public async Task Provider_RecordedReply_ReachesTheSameVerdictAsTheGate(string responseFile)
    {
        // The gate tests prove the comparison; this proves the pipeline around it. Each
        // recorded reply is served through the provider's transport seam, so prompt
        // assembly, deserialization, the gate and the fallback all run exactly as they do
        // against the live API — and the user-visible outcome (a live explanation versus
        // the deterministic fallback) must agree with the per-reply verdict.
        ReplayEntry entry = ReplayCorpus.Entries.Single(candidate => candidate.ResponseFile == responseFile);
        WorkflowAnalysisResult analysis = CorpusEval.AnalyzeForReplay(entry.WorkflowFile);
        string reply = File.ReadAllText(Path.Join(ResponsesDirectory, entry.ResponseFile));

        var provider = new OpenAiWorkflowAiProvider(
            new OpenAiOptions { ApiKey = string.Empty, Model = "test", TimeoutSeconds = 5, MaximumContextCharacters = 10_000 },
            Microsoft.Extensions.Logging.Abstractions.NullLogger<OpenAiWorkflowAiProvider>.Instance,
            (_, _, _) => Task.FromResult(reply));

        WorkflowAiExplanation explanation =
            await provider.ExplainAsync(analysis, "sanitized", CancellationToken.None);

        Assert.Equal(entry.ShouldBeAccepted, explanation.GeneratedByAi);
    }

    [Fact]
    public void ContainmentGate_InventedRuleId_IsNeverAccepted()
    {
        // Stated once, over the whole corpus, rather than left implicit in the per-reply
        // expectations. This is the sentence the README makes; if it stops being true, the
        // failure should name that claim rather than a file.
        string[] escaped = [.. ReplayCorpus.Entries
            .Select(entry => new
            {
                entry.ResponseFile,
                Analysis = CorpusEval.AnalyzeForReplay(entry.WorkflowFile),
                Payload = Load(entry.ResponseFile)
            })
            .Where(scored => scored.Payload.Findings.Any(finding =>
                !scored.Analysis.Findings
                    .Select(real => real.RuleId)
                    .Contains(finding.RuleId, StringComparer.Ordinal)))
            .Where(scored => OpenAiWorkflowAiProvider.IsValid(scored.Payload, scored.Analysis))
            .Select(scored => scored.ResponseFile)];

        Assert.True(
            escaped.Length == 0,
            "Replies naming a rule the scanner never produced, accepted by the gate: "
            + string.Join(", ", escaped));
    }

    [Fact]
    public void ReplayCorpus_AsDeclared_ContainsInjectionAttempts()
    {
        // Workflow content is attacker-controlled. A corpus with no reply that obeys an
        // injected instruction has not tested the interesting half of the claim.
        bool obedient = ReplayCorpus.Entries.Any(entry =>
            entry.WorkflowFile == "prompt-injection.yml" && !entry.ShouldBeAccepted);

        Assert.True(obedient, "No reply in the corpus obeys the injected instruction.");
    }

    [Fact]
    public void ReplayCorpus_RecordedReplies_AreAllDeclared()
    {
        string[] declared = [.. ReplayCorpus.Entries.Select(entry => entry.ResponseFile)];
        string[] undeclared = [.. Directory.EnumerateFiles(ResponsesDirectory, "*.json")
            .Select(Path.GetFileName)
            .OfType<string>()
            .Except(declared, StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)];

        Assert.True(
            undeclared.Length == 0,
            $"Present in Responses/ but unscored: {string.Join(", ", undeclared)}. "
            + "A captured reply nobody declared looks like coverage and contributes nothing.");
    }

    [Fact]
    public void ReplayCorpus_AfterReplay_WritesTheScoreboard()
    {
        List<string> lines =
        [
            "# Containment replay scoreboard",
            "",
            $"{ReplayCorpus.Entries.Count} recorded replies.",
            "",
            "| Reply | Workflow | Expected | Actual | Result |",
            "|---|---|---|---|---|"
        ];

        static string Verdict(bool value) => value ? "accepted" : "rejected";

        lines.AddRange(ReplayCorpus.Entries
            .Select(entry => new
            {
                entry.ResponseFile,
                entry.WorkflowFile,
                entry.ShouldBeAccepted,
                Accepted = OpenAiWorkflowAiProvider.IsValid(
                    Load(entry.ResponseFile),
                    CorpusEval.AnalyzeForReplay(entry.WorkflowFile))
            })
            .Select(row =>
                $"| `{row.ResponseFile}` | `{row.WorkflowFile}` | {Verdict(row.ShouldBeAccepted)} "
                + $"| {Verdict(row.Accepted)} | {(row.Accepted == row.ShouldBeAccepted ? "pass" : "**FAIL**")} |"));

        string path = Path.Join(AppContext.BaseDirectory, "replay-scoreboard.md");
        File.WriteAllLines(path, lines);

        // Assert.True(true) was the assertion here, which made this a method
        // that could not fail — the scoreboard could be empty, truncated or
        // never written and the test still passed.
        string[] written = File.ReadAllLines(path);

        Assert.Equal(
            ReplayCorpus.Entries.Count,
            written.Count(line => line.StartsWith("| `", StringComparison.Ordinal)));
        Assert.DoesNotContain("**FAIL**", written);
    }

    private static string ResponsesDirectory => Path.Join(AppContext.BaseDirectory, "Responses");

    private static OpenAiWorkflowAiProvider.OpenAiExplanationPayload Load(string responseFile)
    {
        string json = File.ReadAllText(Path.Join(ResponsesDirectory, responseFile));
        return JsonSerializer.Deserialize<OpenAiWorkflowAiProvider.OpenAiExplanationPayload>(json, JsonOptions)
            ?? throw new InvalidOperationException($"{responseFile} did not deserialise.");
    }
}
