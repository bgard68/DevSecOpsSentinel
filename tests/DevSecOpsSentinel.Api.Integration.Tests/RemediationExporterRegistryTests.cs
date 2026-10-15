using DevSecOpsSentinel.Api;

namespace DevSecOpsSentinel.Api.Integration.Tests;

/// <summary>
/// The export endpoint quotes a list of supported formats back to a caller who asks for one
/// that does not exist. That list used to be a hand-written string beside the switch that
/// accepted the formats, so it could name a format that had been removed, or omit one that
/// had been added, and nothing would notice until someone read the error message they got
/// for a format the API in fact supports.
///
/// These tests hold the message to the registry that answers the request.
/// </summary>
public sealed class RemediationExporterRegistryTests
{
    [Theory]
    [InlineData("markdown")]
    [InlineData("html")]
    [InlineData("sarif")]
    [InlineData("json")]
    [InlineData("diff")]
    public void CanonicalFormat_IsResolvedAndAdvertised(string format)
    {
        Assert.NotNull(RemediationExporters.For(format));

        Assert.Contains(
            format,
            RemediationExporters.SupportedFormats,
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("md", "markdown")]
    [InlineData("patch", "diff")]
    public void Alias_ResolvesToItsCanonicalFormat(string alias, string canonical)
    {
        Assert.Equal(
            RemediationExporters.For(canonical)?.Format,
            RemediationExporters.For(alias)?.Format);
    }

    [Theory]
    [InlineData("MARKDOWN")]
    [InlineData("Sarif")]
    [InlineData("MD")]
    public void Format_IsMatchedWithoutRegardToCase(string format)
    {
        // The route segment was previously lowercased before the switch saw it, so this is
        // existing behaviour rather than a new allowance.
        Assert.NotNull(RemediationExporters.For(format));
    }

    [Theory]
    [InlineData("pdf")]
    [InlineData("")]
    [InlineData("sarif2")]
    public void UnknownFormat_ResolvesToNothing(string format)
    {
        Assert.Null(RemediationExporters.For(format));
    }

    [Fact]
    public void EveryAdvertisedFormat_IsAcceptedByTheResolver()
    {
        // The direction that caught the original defect: a name in the message that the
        // endpoint would reject.
        foreach (string advertised in RemediationExporters.SupportedFormats
            .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            Assert.NotNull(RemediationExporters.For(advertised));
        }
    }
}
