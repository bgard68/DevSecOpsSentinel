using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;
using DevSecOpsSentinel.Infrastructure.Ai;

namespace DevSecOpsSentinel.Infrastructure.Tests;

/// <summary>
/// Unit tests for the two providers that never contact OpenAI, and for the
/// selector that decides which provider a caller reaches.
///
/// The selector is the control that stops an anonymous visitor spending credits
/// on a deployment configured Live, so its two branches are asserted by
/// reference identity rather than by anything the providers happen to return.
/// </summary>
public sealed class WorkflowAiProviderTests
{
    private static WorkflowAnalysisResult Analysis(params WorkflowFinding[] findings) =>
        new("build.yml", true, [], findings, null);

    private static WorkflowFinding Finding(
        string ruleId = "GHA002",
        WorkflowSeverity severity = WorkflowSeverity.High,
        string description = "The workflow grants write-all.",
        string recommendation = "Scope the permissions block.") =>
        new(ruleId, severity, "Title", description, 4, recommendation, true);

    // -------------------------------------------------- MockWorkflowAiProvider

    [Fact]
    public async Task MockExplainAsync_AnalysisWithFindings_LabelsItselfMockAndNotGeneratedByAi()
    {
        // Arrange. The mode and the flag are what the client renders as the
        // provenance badge. Mislabelling a canned answer as model output is the
        // single claim this project cannot make.
        MockWorkflowAiProvider provider = new();

        // Act
        WorkflowAiExplanation explanation = await provider.ExplainAsync(
            Analysis(Finding()),
            "sanitized",
            CancellationToken.None);

        // Assert
        Assert.Equal("Mock", explanation.Mode);
        Assert.False(explanation.GeneratedByAi);
        Assert.Equal(
            "The workflow contains 1 deterministic security finding(s) that should be reviewed.",
            explanation.Summary);
    }

    [Fact]
    public async Task MockExplainAsync_AnalysisWithFindings_EchoesEveryRuleIdAndRecommendationUnchanged()
    {
        // Arrange. The mock must not invent, drop or rename a finding, which is
        // the same containment rule the live provider is held to.
        MockWorkflowAiProvider provider = new();

        WorkflowAnalysisResult analysis = Analysis(
            Finding("GHA002", WorkflowSeverity.High, "Grants write-all.", "Scope it."),
            Finding("GHA003", WorkflowSeverity.Medium, "No timeout.", "Add timeout-minutes."));

        // Act
        WorkflowAiExplanation explanation = await provider.ExplainAsync(
            analysis,
            "sanitized",
            CancellationToken.None);

        // Assert
        Assert.Equal(
            ["GHA002", "GHA003"],
            explanation.Findings.Select(finding => finding.RuleId));

        Assert.Equal(
            ["Scope it.", "Add timeout-minutes."],
            explanation.Findings.Select(finding => finding.RecommendedAction));

        Assert.Equal(
            "Grants write-all. This explanation is produced by the cost-free mock provider.",
            explanation.Findings[0].WhyItMatters);
    }

    [Fact]
    public async Task MockExplainAsync_CleanAnalysis_ReturnsTheNoViolationsSummaryAndNoFindings()
    {
        // Arrange
        MockWorkflowAiProvider provider = new();

        // Act
        WorkflowAiExplanation explanation = await provider.ExplainAsync(
            Analysis(),
            "sanitized",
            CancellationToken.None);

        // Assert
        Assert.Equal(
            "No configured rule violations were detected. Continue normal review and testing.",
            explanation.Summary);
        Assert.Empty(explanation.Findings);
    }

    [Fact]
    public async Task MockExplainAsync_AnyAnalysis_StatesThatItSpentNothing()
    {
        // Arrange. These two lines are the user-facing claim that the mock
        // reached nothing; dropping them makes the badge unverifiable.
        MockWorkflowAiProvider provider = new();

        // Act
        WorkflowAiExplanation explanation = await provider.ExplainAsync(
            Analysis(Finding()),
            "sanitized",
            CancellationToken.None);

        // Assert
        Assert.Equal(
            [
                "Mock mode does not contact OpenAI or consume API credits.",
                "The deterministic rule engine remains the source of truth."
            ],
            explanation.Limitations);
    }

    [Fact]
    public async Task MockExplainAsync_CancellationAlreadyRequested_ThrowsRatherThanReturningAnExplanation()
    {
        // Arrange
        MockWorkflowAiProvider provider = new();
        using CancellationTokenSource source = new();
        await source.CancelAsync();

        // Act & Assert
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => provider.ExplainAsync(Analysis(Finding()), "sanitized", source.Token));
    }

    // ---------------------------------------------- DisabledWorkflowAiProvider

    [Fact]
    public async Task DisabledExplainAsync_AnalysisWithFindings_ReturnsTheDeterministicFallbackWithItsReason()
    {
        // Arrange
        DisabledWorkflowAiProvider provider = new();

        // Act
        WorkflowAiExplanation explanation = await provider.ExplainAsync(
            Analysis(Finding()),
            "sanitized",
            CancellationToken.None);

        // Assert
        Assert.Equal("Disabled", explanation.Mode);
        Assert.False(explanation.GeneratedByAi);
        Assert.Equal(
            "OpenAI integration is disabled by configuration.",
            explanation.FallbackReason);
        Assert.Equal(
            "The deterministic scanner identified 1 finding(s).",
            explanation.Summary);
    }

    [Fact]
    public async Task DisabledExplainAsync_AnalysisWithFindings_CarriesRuleTextThroughVerbatim()
    {
        // Arrange. The fallback restates the rule's own description and
        // recommendation. Any embellishment here would be text no rule wrote.
        DisabledWorkflowAiProvider provider = new();

        // Act
        WorkflowAiExplanation explanation = await provider.ExplainAsync(
            Analysis(Finding("GHA004", WorkflowSeverity.Critical, "Privileged trigger.", "Use pull_request.")),
            "sanitized",
            CancellationToken.None);

        // Assert
        AiFindingExplanation finding = Assert.Single(explanation.Findings);

        Assert.Equal("GHA004", finding.RuleId);
        Assert.Equal("Privileged trigger.", finding.WhyItMatters);
        Assert.Equal("Use pull_request.", finding.RecommendedAction);
        Assert.Equal("deterministic", finding.Confidence);
    }

    [Fact]
    public async Task DisabledExplainAsync_CleanAnalysis_ReportsNoViolationsWithoutClaimingAiInvolvement()
    {
        // Arrange
        DisabledWorkflowAiProvider provider = new();

        // Act
        WorkflowAiExplanation explanation = await provider.ExplainAsync(
            Analysis(),
            "sanitized",
            CancellationToken.None);

        // Assert
        Assert.Equal(
            "The deterministic scanner did not identify any configured rule violations.",
            explanation.Summary);
        Assert.Empty(explanation.Findings);
        Assert.False(explanation.GeneratedByAi);
        Assert.Equal(
            ["This fallback was generated without a live OpenAI request."],
            explanation.Limitations);
    }

    // ------------------------------------------- WorkflowAiProviderSelector

    [Fact]
    public void Select_ConfiguredAccess_ReturnsTheConfiguredProviderInstance()
    {
        // Arrange
        DisabledWorkflowAiProvider configured = new();
        MockWorkflowAiProvider mock = new();
        WorkflowAiProviderSelector selector = new(configured, mock);

        // Act
        IWorkflowAiProvider selected = selector.Select(AiCallerAccess.Configured);

        // Assert
        Assert.Same(configured, selected);
    }

    [Fact]
    public void Select_MockOnlyAccess_ReturnsTheMockProviderNotTheConfiguredOne()
    {
        // Arrange. This is the control that keeps an anonymous caller from
        // driving a live model call on a deployment configured for one.
        DisabledWorkflowAiProvider configured = new();
        MockWorkflowAiProvider mock = new();
        WorkflowAiProviderSelector selector = new(configured, mock);

        // Act
        IWorkflowAiProvider selected = selector.Select(AiCallerAccess.MockOnly);

        // Assert
        Assert.Same(mock, selected);
        Assert.NotSame(configured, selected);
    }

    [Fact]
    public void Select_UndefinedAccessValue_FallsBackToMockRatherThanTheConfiguredProvider()
    {
        // Arrange. An enum cast from an out-of-range integer is the shape a
        // future third access level would arrive in. The comparison is against
        // Configured, so anything unrecognised must fail closed onto Mock.
        DisabledWorkflowAiProvider configured = new();
        MockWorkflowAiProvider mock = new();
        WorkflowAiProviderSelector selector = new(configured, mock);

        // Act
        IWorkflowAiProvider selected = selector.Select((AiCallerAccess)99);

        // Assert
        Assert.Same(mock, selected);
    }

    [Fact]
    public void Select_CalledRepeatedly_ReturnsTheSameInstancesWithoutReallocating()
    {
        // Arrange. The selector runs per request; allocating a provider each
        // time would discard whatever state the configured provider holds,
        // including its HTTP client and its cache.
        DisabledWorkflowAiProvider configured = new();
        MockWorkflowAiProvider mock = new();
        WorkflowAiProviderSelector selector = new(configured, mock);

        // Act
        IWorkflowAiProvider firstConfigured = selector.Select(AiCallerAccess.Configured);
        IWorkflowAiProvider secondConfigured = selector.Select(AiCallerAccess.Configured);
        IWorkflowAiProvider firstMock = selector.Select(AiCallerAccess.MockOnly);

        // Assert
        Assert.Same(firstConfigured, secondConfigured);
        Assert.NotSame(firstConfigured, firstMock);
    }
}
