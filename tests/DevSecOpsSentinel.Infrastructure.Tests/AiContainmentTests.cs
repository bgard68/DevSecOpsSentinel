using DevSecOpsSentinel.Domain;
using DevSecOpsSentinel.Infrastructure.Ai;

namespace DevSecOpsSentinel.Infrastructure.Tests;

/// <summary>
/// ADR-003 says the model is not a source of truth: deterministic rules decide what is
/// wrong, and the model only explains what they already found. The whole claim rests on
/// one gate — <see cref="OpenAiWorkflowAiProvider.IsValid"/> — which compares the rule ids
/// in the model's reply against the rule ids the scanner produced and rejects the reply
/// outright on any mismatch. A rejected reply becomes the deterministic fallback, so a
/// finding the model made up never reaches a user.
///
/// These tests exercise that gate directly, with no network call, because a claim that
/// strong should fail a build rather than a demo.
/// </summary>
public sealed class AiContainmentTests
{
    private const string Unpinned = "GHA001";
    private const string Excessive = "GHA002";
    private const string Invented = "GHA999";

    [Fact]
    public void Reply_naming_exactly_the_scanner_findings_is_accepted()
    {
        var analysis = AnalysisWith(Unpinned, Excessive);
        var payload = PayloadWith(Unpinned, Excessive);

        Assert.True(OpenAiWorkflowAiProvider.IsValid(payload, analysis));
    }

    [Fact]
    public void Reply_inventing_a_rule_the_scanner_did_not_find_is_rejected()
    {
        // The headline case: the model asserts a vulnerability of its own. Even though the
        // real findings are all present and correctly described, the extra id fails the gate.
        var analysis = AnalysisWith(Unpinned, Excessive);
        var payload = PayloadWith(Unpinned, Excessive, Invented);

        Assert.False(OpenAiWorkflowAiProvider.IsValid(payload, analysis));
    }

    [Fact]
    public void Reply_consisting_only_of_invented_rules_is_rejected()
    {
        var analysis = AnalysisWith(Unpinned);
        var payload = PayloadWith(Invented);

        Assert.False(OpenAiWorkflowAiProvider.IsValid(payload, analysis));
    }

    [Fact]
    public void Reply_silently_dropping_a_finding_is_rejected()
    {
        // Containment runs both ways. A reply that quietly omits a real finding would let the
        // model decide something is not worth mentioning, which is the same authority in reverse.
        var analysis = AnalysisWith(Unpinned, Excessive);
        var payload = PayloadWith(Unpinned);

        Assert.False(OpenAiWorkflowAiProvider.IsValid(payload, analysis));
    }

    [Fact]
    public void Reply_swapping_one_real_rule_for_another_is_rejected()
    {
        // Same count as the scanner produced, so a length check alone would pass this.
        var analysis = AnalysisWith(Unpinned, Excessive);
        var payload = PayloadWith(Unpinned, Invented);

        Assert.False(OpenAiWorkflowAiProvider.IsValid(payload, analysis));
    }

    [Theory]
    [InlineData("gha001")]
    [InlineData("GHA001 ")]
    [InlineData(" GHA001")]
    public void Rule_ids_are_matched_exactly_and_not_loosely(string nearMiss)
    {
        // Comparison is ordinal on purpose. A near miss is a reply the gate cannot vouch for,
        // so it degrades to the deterministic fallback rather than being quietly normalised.
        var analysis = AnalysisWith(Unpinned);
        var payload = PayloadWith(nearMiss);

        Assert.False(OpenAiWorkflowAiProvider.IsValid(payload, analysis));
    }

    [Fact]
    public void Clean_workflow_accepts_a_reply_that_claims_nothing()
    {
        var analysis = AnalysisWith();
        var payload = PayloadWith();

        Assert.True(OpenAiWorkflowAiProvider.IsValid(payload, analysis));
    }

    [Fact]
    public void Clean_workflow_rejects_a_reply_that_manufactures_a_finding()
    {
        // safe.yml in the sandbox exists for this case: nothing found, so nothing to explain.
        var analysis = AnalysisWith();
        var payload = PayloadWith(Invented);

        Assert.False(OpenAiWorkflowAiProvider.IsValid(payload, analysis));
    }

    [Theory]
    [InlineData("", "next step")]
    [InlineData("   ", "next step")]
    [InlineData("summary", "")]
    [InlineData("summary", "   ")]
    public void Reply_missing_its_prose_is_rejected_even_when_the_rule_ids_line_up(
        string summary,
        string nextStep)
    {
        // A reply with the right ids but no explanation is not an explanation. Falling back
        // gives the user the deterministic finding text instead of an empty panel.
        var analysis = AnalysisWith(Unpinned);
        var payload = new OpenAiWorkflowAiProvider.OpenAiExplanationPayload(
            summary,
            [Finding(Unpinned)],
            nextStep,
            []);

        Assert.False(OpenAiWorkflowAiProvider.IsValid(payload, analysis));
    }

    private static WorkflowAnalysisResult AnalysisWith(params string[] ruleIds) =>
        new(
            "workflow.yml",
            IsValid: true,
            ValidationErrors: [],
            Findings: [.. ruleIds.Select(id => new WorkflowFinding(
                id,
                WorkflowSeverity.High,
                $"{id} title",
                $"{id} description",
                LineNumber: 1,
                Recommendation: $"{id} recommendation",
                IsAutomaticallyFixable: false))],
            Patch: null);

    private static OpenAiWorkflowAiProvider.OpenAiExplanationPayload PayloadWith(params string[] ruleIds) =>
        new(
            "A summary the model produced.",
            [.. ruleIds.Select(Finding)],
            "A recommended next step.",
            []);

    private static OpenAiWorkflowAiProvider.OpenAiFindingPayload Finding(string ruleId) =>
        new(ruleId, "why it matters", "recommended action", "high");
}
