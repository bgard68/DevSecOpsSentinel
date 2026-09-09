using DevSecOpsSentinel.Domain;
using DevSecOpsSentinel.Infrastructure.Ai;
using Microsoft.Extensions.Logging.Abstractions;

namespace DevSecOpsSentinel.Infrastructure.Tests;

/// <summary>
/// The live path, end to end, with only the transport substituted.
///
/// Until the seam existed, everything between "request assembled" and "containment gate"
/// ran only against the real OpenAI API — which is to say it ran in production and nowhere
/// else. These tests drive the exact pipeline production uses: prompt assembly, the
/// timeout envelope, deserialization, the gate, and every fallback branch.
/// </summary>
public sealed class OpenAiWorkflowAiProviderTests
{
    private static readonly OpenAiOptions Options = new()
    {
        ApiKey = string.Empty,
        Model = "gpt-5-mini",
        TimeoutSeconds = 5,
        MaximumContextCharacters = 200
    };

    private static WorkflowAnalysisResult Analysis(params string[] ruleIds) =>
        new(
            "workflow.yml",
            IsValid: true,
            ValidationErrors: [],
            Findings: [.. ruleIds.Select(id => new WorkflowFinding(
                id, WorkflowSeverity.High, $"{id} title", $"{id} description",
                LineNumber: 1, Recommendation: $"{id} fix", IsAutomaticallyFixable: false))],
            Patch: null);

    private static OpenAiWorkflowAiProvider Provider(OpenAiWorkflowAiProvider.CompleteChat completeChat) =>
        new(Options, NullLogger<OpenAiWorkflowAiProvider>.Instance, completeChat);

    private static string ValidReply(params string[] ruleIds) =>
        System.Text.Json.JsonSerializer.Serialize(new
        {
            summary = "What the findings mean together.",
            findings = ruleIds.Select(id => new
            {
                ruleId = id,
                whyItMatters = "why",
                recommendedAction = "action",
                confidence = "high"
            }),
            recommendedNextStep = "Fix the pin first.",
            limitations = Array.Empty<string>()
        });

    [Fact]
    public async Task ExplainAsync_ValidReply_BecomesALiveExplanation()
    {
        var provider = Provider((_, _, _) => Task.FromResult(ValidReply("GHA001")));

        WorkflowAiExplanation explanation =
            await provider.ExplainAsync(Analysis("GHA001"), "on: push", CancellationToken.None);

        Assert.True(explanation.GeneratedByAi);
        Assert.Equal("Live", explanation.Mode);
        Assert.Equal("GHA001", Assert.Single(explanation.Findings).RuleId);
        Assert.Null(explanation.FallbackReason);
    }

    [Fact]
    public async Task ExplainAsync_AnyRequest_SendsThePromptWithFindingsAndSanitizedContent()
    {
        string? prompt = null;
        var provider = Provider((messages, _, _) =>
        {
            prompt = messages[^1].Content[0].Text;
            return Task.FromResult(ValidReply("GHA002"));
        });

        await provider.ExplainAsync(Analysis("GHA002"), "permissions: write-all", CancellationToken.None);

        Assert.NotNull(prompt);
        Assert.Contains("GHA002", prompt);
        Assert.Contains("permissions: write-all", prompt);
    }

    [Fact]
    public async Task ExplainAsync_ContextBeyondTheConfiguredMaximum_IsTruncatedBeforeItIsSent()
    {
        string? prompt = null;
        var provider = Provider((messages, _, _) =>
        {
            prompt = messages[^1].Content[0].Text;
            return Task.FromResult(ValidReply("GHA001"));
        });

        string oversized = new('x', Options.MaximumContextCharacters + 50);
        await provider.ExplainAsync(Analysis("GHA001"), oversized, CancellationToken.None);

        Assert.NotNull(prompt);
        Assert.DoesNotContain(oversized, prompt);
        Assert.Contains(new string('x', Options.MaximumContextCharacters), prompt);
    }

    [Fact]
    public async Task ExplainAsync_ReplyThatFailsTheGate_DegradesToTheDeterministicFallback()
    {
        var provider = Provider((_, _, _) => Task.FromResult(ValidReply("GHA999")));

        WorkflowAiExplanation explanation =
            await provider.ExplainAsync(Analysis("GHA001"), "on: push", CancellationToken.None);

        Assert.False(explanation.GeneratedByAi);
        Assert.Equal("OpenAI returned an invalid structured explanation.", explanation.FallbackReason);
        // The fallback still explains the real finding; the user loses polish, not facts.
        Assert.Equal("GHA001", Assert.Single(explanation.Findings).RuleId);
    }

    [Fact]
    public async Task ExplainAsync_ReplyThatIsNotJson_DegradesRatherThanThrows()
    {
        var provider = Provider((_, _, _) => Task.FromResult("I am not JSON."));

        WorkflowAiExplanation explanation =
            await provider.ExplainAsync(Analysis("GHA001"), "on: push", CancellationToken.None);

        Assert.False(explanation.GeneratedByAi);
        Assert.NotNull(explanation.FallbackReason);
    }

    [Fact]
    public async Task ExplainAsync_TransportFailure_DegradesToTheUnavailableFallback()
    {
        var provider = Provider((_, _, _) =>
            Task.FromException<string>(new HttpRequestException("boom")));

        WorkflowAiExplanation explanation =
            await provider.ExplainAsync(Analysis("GHA001"), "on: push", CancellationToken.None);

        Assert.False(explanation.GeneratedByAi);
        Assert.Equal("The OpenAI provider was unavailable.", explanation.FallbackReason);
    }

    [Fact]
    public async Task ExplainAsync_RequestThatOutlivesTheTimeout_ReportsTheTimeout()
    {
        // The delegate honours the token it is handed — the token the provider's own
        // timeout envelope controls. Nothing here waits five seconds; the envelope is
        // driven by the option, and the option is one second above the clamp floor.
        var provider = new OpenAiWorkflowAiProvider(
            new OpenAiOptions { ApiKey = string.Empty, Model = "m", TimeoutSeconds = 5, MaximumContextCharacters = 200 },
            NullLogger<OpenAiWorkflowAiProvider>.Instance,
            async (_, _, cancellationToken) =>
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                return "unreachable";
            });

        WorkflowAiExplanation explanation =
            await provider.ExplainAsync(Analysis("GHA001"), "on: push", CancellationToken.None);

        Assert.False(explanation.GeneratedByAi);
        Assert.Equal("The OpenAI request timed out.", explanation.FallbackReason);
    }

    [Fact]
    public async Task ExplainAsync_NoApiKeyConfigured_DegradesBeforeAnyRequest()
    {
        var provider = new OpenAiWorkflowAiProvider(
            new OpenAiOptions { ApiKey = "  ", Model = "m" },
            NullLogger<OpenAiWorkflowAiProvider>.Instance);

        WorkflowAiExplanation explanation =
            await provider.ExplainAsync(Analysis("GHA001"), "on: push", CancellationToken.None);

        Assert.False(explanation.GeneratedByAi);
        Assert.Equal(
            "OpenAI is configured for live mode, but no API key is available.",
            explanation.FallbackReason);
    }
}
