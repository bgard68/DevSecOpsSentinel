using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Application.Tests;

/// <summary>
/// The routing above the providers: which caller gets which provider, and which
/// situations never reach a provider at all. The second half is the security-relevant
/// one — invalid YAML and un-requested AI must short-circuit before anything that
/// could cost money runs.
/// </summary>
public sealed class WorkflowExplanationServiceTests
{
    private sealed class FakeAnalysis(WorkflowAnalysisResult result) : IWorkflowAnalysisService
    {
        public Task<WorkflowAnalysisResult> AnalyzeAsync(
            WorkflowDocument document,
            CancellationToken cancellationToken) => Task.FromResult(result);
    }

    private sealed class RecordingProvider(string label) : IWorkflowAiProvider
    {
        public int Calls { get; private set; }

        public Task<WorkflowAiExplanation> ExplainAsync(
            WorkflowAnalysisResult analysis,
            string sanitizedContent,
            CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new WorkflowAiExplanation(
                $"from {label}", [], "next", [], GeneratedByAi: true, Mode: label));
        }
    }

    private sealed class RecordingSelector(IWorkflowAiProvider provider) : IWorkflowAiProviderSelector
    {
        public AiCallerAccess? SelectedWith { get; private set; }

        public IWorkflowAiProvider Select(AiCallerAccess access)
        {
            SelectedWith = access;
            return provider;
        }
    }

    private sealed class PassthroughSanitizer : ISensitiveDataSanitizer
    {
        public SanitizedWorkflow Sanitize(string content) => new(content, WasRedacted: false);
    }

    private static WorkflowAnalysisResult Valid() =>
        new("wf.yml", IsValid: true, [], [], Patch: null);

    private static WorkflowAnalysisResult Invalid() =>
        new("wf.yml", IsValid: false, ["bad yaml"], [], Patch: null);

    private static WorkflowDocument Document() => new("wf.yml", "name: x\non:\n  push:\n");

    [Fact]
    public async Task Invalid_yaml_never_reaches_a_provider()
    {
        RecordingProvider provider = new("Live");
        RecordingSelector selector = new(provider);
        var service = new WorkflowExplanationService(
            new FakeAnalysis(Invalid()), selector, new PassthroughSanitizer());

        WorkflowExplanationResult result = await service.ExplainAsync(
            Document(), useAi: true, AiCallerAccess.Configured, CancellationToken.None);

        Assert.Equal(0, provider.Calls);
        Assert.Equal("Deterministic", result.Explanation.Mode);
        Assert.False(result.Explanation.GeneratedByAi);
    }

    [Fact]
    public async Task Unrequested_ai_never_reaches_a_provider()
    {
        RecordingProvider provider = new("Live");
        RecordingSelector selector = new(provider);
        var service = new WorkflowExplanationService(
            new FakeAnalysis(Valid()), selector, new PassthroughSanitizer());

        WorkflowExplanationResult result = await service.ExplainAsync(
            Document(), useAi: false, AiCallerAccess.Configured, CancellationToken.None);

        Assert.Equal(0, provider.Calls);
        Assert.Equal("Disabled", result.Explanation.Mode);
    }

    [Theory]
    [InlineData(AiCallerAccess.MockOnly)]
    [InlineData(AiCallerAccess.Configured)]
    public async Task The_callers_access_level_is_what_reaches_the_selector(AiCallerAccess access)
    {
        // The selector is where "anonymous callers cannot spend" is decided, so the
        // access value must arrive exactly as the endpoint stated it.
        RecordingProvider provider = new("Selected");
        RecordingSelector selector = new(provider);
        var service = new WorkflowExplanationService(
            new FakeAnalysis(Valid()), selector, new PassthroughSanitizer());

        WorkflowExplanationResult result = await service.ExplainAsync(
            Document(), useAi: true, access, CancellationToken.None);

        Assert.Equal(access, selector.SelectedWith);
        Assert.Equal(1, provider.Calls);
        Assert.True(result.Explanation.GeneratedByAi);
    }

    [Fact]
    public async Task Redaction_flag_travels_from_the_sanitizer_to_the_result()
    {
        var service = new WorkflowExplanationService(
            new FakeAnalysis(Valid()),
            new RecordingSelector(new RecordingProvider("Live")),
            new RedactingSanitizer());

        WorkflowExplanationResult result = await service.ExplainAsync(
            Document(), useAi: true, AiCallerAccess.Configured, CancellationToken.None);

        Assert.True(result.SensitiveContentRedacted);
    }

    private sealed class RedactingSanitizer : ISensitiveDataSanitizer
    {
        public SanitizedWorkflow Sanitize(string content) => new("[redacted]", WasRedacted: true);
    }

    [Fact]
    public void The_fallback_carries_every_deterministic_finding()
    {
        WorkflowAnalysisResult analysis = new(
            "wf.yml", IsValid: true, [],
            [
                new WorkflowFinding("GHA001", WorkflowSeverity.High, "t", "d", 1, "r", false),
                new WorkflowFinding("GHA002", WorkflowSeverity.High, "t", "d", 2, "r", false)
            ],
            Patch: null);

        WorkflowAiExplanation fallback = AiExplanationFactory.CreateFallback(analysis, "Mode", "why");

        Assert.Equal(2, fallback.Findings.Count);
        Assert.Contains("2 finding(s)", fallback.Summary);
        Assert.Equal("why", fallback.FallbackReason);
        Assert.False(fallback.GeneratedByAi);
    }
}
