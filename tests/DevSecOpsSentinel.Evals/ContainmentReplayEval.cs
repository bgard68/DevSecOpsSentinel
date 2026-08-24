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
    public void Gate_reaches_the_right_verdict(string responseFile)
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

    [Fact]
    public void No_invented_rule_id_is_ever_accepted()
    {
        // Stated once, over the whole corpus, rather than left implicit in the per-reply
        // expectations. This is the sentence the README makes; if it stops being true, the
        // failure should name that claim rather than a file.
        List<string> escaped = [];

        foreach (ReplayEntry entry in ReplayCorpus.Entries)
        {
            WorkflowAnalysisResult analysis = CorpusEval.AnalyzeForReplay(entry.WorkflowFile);
            OpenAiWorkflowAiProvider.OpenAiExplanationPayload payload = Load(entry.ResponseFile);

            HashSet<string> real = [.. analysis.Findings.Select(finding => finding.RuleId)];
            bool invents = payload.Findings.Any(finding => !real.Contains(finding.RuleId));

            if (invents && OpenAiWorkflowAiProvider.IsValid(payload, analysis))
            {
                escaped.Add(entry.ResponseFile);
            }
        }

        Assert.True(
            escaped.Count == 0,
            "Replies naming a rule the scanner never produced, accepted by the gate: "
            + string.Join(", ", escaped));
    }

    [Fact]
    public void Injection_attempts_are_represented_in_the_corpus()
    {
        // Workflow content is attacker-controlled. A corpus with no reply that obeys an
        // injected instruction has not tested the interesting half of the claim.
        bool obedient = ReplayCorpus.Entries.Any(entry =>
            entry.WorkflowFile == "prompt-injection.yml" && !entry.ShouldBeAccepted);

        Assert.True(obedient, "No reply in the corpus obeys the injected instruction.");
    }

    [Fact]
    public void Every_recorded_reply_is_declared()
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
    public void Write_replay_scoreboard()
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

        foreach (ReplayEntry entry in ReplayCorpus.Entries)
        {
            WorkflowAnalysisResult analysis = CorpusEval.AnalyzeForReplay(entry.WorkflowFile);
            bool accepted = OpenAiWorkflowAiProvider.IsValid(Load(entry.ResponseFile), analysis);
            string verdict(bool value) => value ? "accepted" : "rejected";

            lines.Add(
                $"| `{entry.ResponseFile}` | `{entry.WorkflowFile}` | {verdict(entry.ShouldBeAccepted)} "
                + $"| {verdict(accepted)} | {(accepted == entry.ShouldBeAccepted ? "pass" : "**FAIL**")} |");
        }

        File.WriteAllLines(Path.Join(AppContext.BaseDirectory, "replay-scoreboard.md"), lines);
        Assert.True(true);
    }

    private static string ResponsesDirectory => Path.Join(AppContext.BaseDirectory, "Responses");

    private static OpenAiWorkflowAiProvider.OpenAiExplanationPayload Load(string responseFile)
    {
        string json = File.ReadAllText(Path.Join(ResponsesDirectory, responseFile));
        return JsonSerializer.Deserialize<OpenAiWorkflowAiProvider.OpenAiExplanationPayload>(json, JsonOptions)
            ?? throw new InvalidOperationException($"{responseFile} did not deserialise.");
    }
}
