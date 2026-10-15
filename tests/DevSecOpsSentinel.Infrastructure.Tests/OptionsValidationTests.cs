using DevSecOpsSentinel.Infrastructure.Ai;
using DevSecOpsSentinel.Infrastructure.GitHub;
using Microsoft.Extensions.Options;

namespace DevSecOpsSentinel.Infrastructure.Tests;

/// <summary>
/// The OpenAI and GitHub sections are validated on start, as the API security section
/// already was. These tests pin both directions: what is rejected, and — just as important
/// — what has to keep being accepted, because an over-eager validator here takes the whole
/// application down over a setting the design deliberately treats as optional.
/// </summary>
public sealed class OptionsValidationTests
{
    private static readonly OpenAiOptionsValidator OpenAi = new();
    private static readonly GitHubOptionsValidator GitHub = new();

    // ------------------------------------------------------------------- OpenAI

    [Fact]
    public void OpenAi_DefaultConfiguration_IsAccepted()
    {
        Assert.True(OpenAi.Validate(null, new OpenAiOptions()).Succeeded);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(4)]
    [InlineData(121)]
    [InlineData(300)]
    public void OpenAi_TimeoutOutsideTheRangeTheProviderHonours_IsRejected(int seconds)
    {
        ValidateOptionsResult result = OpenAi.Validate(
            null,
            new OpenAiOptions { TimeoutSeconds = seconds });

        Assert.True(result.Failed);
        Assert.Contains("TimeoutSeconds", result.FailureMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(999)]
    [InlineData(1_000_001)]
    public void OpenAi_ContextWindowOutsideTheSupportedRange_IsRejected(int characters)
    {
        ValidateOptionsResult result = OpenAi.Validate(
            null,
            new OpenAiOptions { MaximumContextCharacters = characters });

        Assert.True(result.Failed);
        Assert.Contains(
            "MaximumContextCharacters",
            result.FailureMessage,
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(OpenAiOptions.MinimumTimeoutSeconds)]
    [InlineData(30)]
    [InlineData(OpenAiOptions.MaximumTimeoutSeconds)]
    public void OpenAi_TimeoutTheProviderHonours_IsAccepted(int seconds)
    {
        // The boundary from the other side. The validator's range and the provider's clamp
        // read the same constants, so a value accepted here is used as configured rather
        // than quietly adjusted.
        Assert.True(
            OpenAi.Validate(null, new OpenAiOptions { TimeoutSeconds = seconds }).Succeeded);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void OpenAi_BlankModel_IsRejected(string model)
    {
        Assert.True(OpenAi.Validate(null, new OpenAiOptions { Model = model }).Failed);
    }

    [Fact]
    public void OpenAi_UnrecognisedMode_IsNotAStartupFailure()
    {
        // Deliberate. An unrecognised mode warns and resolves to Mock; refusing to start has
        // to be diagnosed from deployment logs, which is the worse of the two failures.
        Assert.True(OpenAi.Validate(null, new OpenAiOptions { Mode = "Lve" }).Succeeded);
    }

    [Fact]
    public void OpenAi_LiveModeWithNoApiKey_IsNotAStartupFailure()
    {
        // Reported by the readiness probe as a degradation, which is the documented
        // behaviour: deterministic analysis does not need OpenAI.
        Assert.True(
            OpenAi.Validate(null, new OpenAiOptions { Mode = "Live", ApiKey = null })
                .Succeeded);
    }

    // ------------------------------------------------------------------- GitHub

    [Fact]
    public void GitHub_DefaultConfiguration_IsAccepted()
    {
        Assert.True(GitHub.Validate(null, new GitHubOptions()).Succeeded);
    }

    [Fact]
    public void GitHub_EnabledButIncomplete_IsNotAStartupFailure()
    {
        // Incomplete is a supported state. The readiness probe reports it; the application
        // still serves deterministic analysis, which needs no GitHub access at all.
        GitHubOptions options = new()
        {
            Enabled = true,
            AppId = 0,
            InstallationId = 0,
            PrivateKeyPath = string.Empty,
            AllowedRepositories = []
        };

        Assert.True(GitHub.Validate(null, options).Succeeded);
        Assert.False(options.IsConfigured);
    }

    [Theory]
    [InlineData(-1, 1)]
    [InlineData(1, -1)]
    public void GitHub_NegativeIdentifiers_AreRejected(long appId, long installationId)
    {
        ValidateOptionsResult result = GitHub.Validate(
            null,
            new GitHubOptions { AppId = appId, InstallationId = installationId });

        Assert.True(result.Failed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("api.github.com")]
    [InlineData("/api")]
    [InlineData("ftp://api.github.com")]
    public void GitHub_ApiBaseUrlThatIsNotAnAbsoluteHttpUrl_IsRejected(string url)
    {
        ValidateOptionsResult result = GitHub.Validate(
            null,
            new GitHubOptions { ApiBaseUrl = url });

        Assert.True(result.Failed);
        Assert.Contains("ApiBaseUrl", result.FailureMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("owner-repository")]
    [InlineData("owner/repository/extra")]
    [InlineData("/repository")]
    [InlineData("owner/")]
    public void GitHub_AllowlistEntryThatCannotMatch_IsRejected(string entry)
    {
        // The failure that matters most here: an entry in this shape never matches, so the
        // configuration file reads as allowing a repository while allowing nothing.
        ValidateOptionsResult result = GitHub.Validate(
            null,
            new GitHubOptions { AllowedRepositories = [entry] });

        Assert.True(result.Failed);
        Assert.Contains("AllowedRepositories", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void GitHub_WellFormedAllowlist_IsAccepted()
    {
        GitHubOptions options = new()
        {
            AllowedRepositories = ["bgard68/DevSecOpsSentinel", "octocat/Hello-World"]
        };

        Assert.True(GitHub.Validate(null, options).Succeeded);
        Assert.True(options.IsAllowed("bgard68", "DevSecOpsSentinel"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void GitHub_BlankAllowlistEntry_IsIgnoredRatherThanRejected(string entry)
    {
        // A configuration provider can materialise an empty slot for a key that was removed.
        // An absent entry allows nothing, which is already the safe direction.
        Assert.True(
            GitHub.Validate(null, new GitHubOptions { AllowedRepositories = [entry] })
                .Succeeded);
    }
}
