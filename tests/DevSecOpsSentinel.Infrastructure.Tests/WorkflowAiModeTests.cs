using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Infrastructure.Ai;
using Microsoft.Extensions.Logging.Abstractions;

namespace DevSecOpsSentinel.Infrastructure.Tests;

/// <summary>
/// The mode setting resolves once, and what the status endpoints report is what the factory
/// built. Previously the composition root and the two status endpoints each read the raw
/// string their own way, so an unrecognised value ran the mock provider while the API went on
/// reporting the string as configured.
/// </summary>
public sealed class WorkflowAiModeTests
{
    [Theory]
    [InlineData("Mock", WorkflowAiMode.Mock)]
    [InlineData("Live", WorkflowAiMode.Live)]
    [InlineData("Disabled", WorkflowAiMode.Disabled)]
    [InlineData("live", WorkflowAiMode.Live)]
    [InlineData("LIVE", WorkflowAiMode.Live)]
    [InlineData("  Live  ", WorkflowAiMode.Live)]
    public void RecognisedMode_Parses(string configured, WorkflowAiMode expected)
    {
        Assert.True(WorkflowAiModes.TryParse(configured, out WorkflowAiMode mode));
        Assert.Equal(expected, mode);
    }

    [Theory]
    [InlineData("Lve")]
    [InlineData("Production")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    // Numeric forms are rejected deliberately: Enum.TryParse would read "1" as Live, which
    // is not a value anyone configures on purpose.
    [InlineData("1")]
    [InlineData("0")]
    public void UnrecognisedMode_DoesNotParseAndFallsBackToMock(string? configured)
    {
        Assert.False(WorkflowAiModes.TryParse(configured, out WorkflowAiMode mode));
        Assert.Equal(WorkflowAiMode.Mock, mode);
        Assert.Equal(WorkflowAiMode.Mock, WorkflowAiModes.Resolve(configured));
    }

    [Fact]
    public void UnrecognisedMode_IsReportedAsTheModeThatWillActuallyRun()
    {
        // The defect this closes. The configured string said one thing, the provider did
        // another, and the status response repeated the string.
        OpenAiOptions options = new() { Mode = "Lve" };

        Assert.Equal(WorkflowAiMode.Mock, options.ResolvedMode);
        Assert.Equal("Mock", options.ResolvedModeName);
        Assert.Equal("Lve", options.Mode);
    }

    [Theory]
    [InlineData("Mock", typeof(MockWorkflowAiProvider))]
    [InlineData("Disabled", typeof(DisabledWorkflowAiProvider))]
    [InlineData("Lve", typeof(MockWorkflowAiProvider))]
    [InlineData("", typeof(MockWorkflowAiProvider))]
    public void Factory_BuildsTheProviderTheResolvedModeNames(
        string configured,
        Type expected)
    {
        IWorkflowAiProvider provider = WorkflowAiProviderFactory.Create(
            new OpenAiOptions { Mode = configured },
            NullLoggerFactory.Instance);

        Assert.IsType(expected, provider);
    }

    [Fact]
    public void Factory_LiveMode_BuildsTheOpenAiProvider()
    {
        // Constructed, not called. A live provider with no key still builds; it fails at the
        // request, which the readiness probe reports as a degradation.
        IWorkflowAiProvider provider = WorkflowAiProviderFactory.Create(
            new OpenAiOptions { Mode = "Live", ApiKey = "sk-not-used-in-this-test" },
            NullLoggerFactory.Instance);

        Assert.IsType<OpenAiWorkflowAiProvider>(provider);
    }

    [Fact]
    public void Factory_ReportedModeAndBuiltProvider_NeverDisagree()
    {
        // The invariant, over every mode name plus a wrong one: whatever the API reports as
        // the mode is the provider the factory returns.
        foreach (string configured in
            (string[])["Mock", "Live", "Disabled", "nonsense", ""])
        {
            OpenAiOptions options = new()
            {
                Mode = configured,
                ApiKey = "sk-not-used-in-this-test"
            };

            IWorkflowAiProvider provider = WorkflowAiProviderFactory.Create(
                options,
                NullLoggerFactory.Instance);

            Type expected = options.ResolvedMode switch
            {
                WorkflowAiMode.Live => typeof(OpenAiWorkflowAiProvider),
                WorkflowAiMode.Disabled => typeof(DisabledWorkflowAiProvider),
                _ => typeof(MockWorkflowAiProvider)
            };

            Assert.IsType(expected, provider);
        }
    }
}
