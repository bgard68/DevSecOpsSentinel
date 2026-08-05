using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace DevSecOpsSentinel.Api.Integration.Tests;

/// <summary>
/// Security:Mode = Public.
///
/// The claim being tested is narrow and worth stating: an anonymous caller can
/// use the deterministic scanner completely, cannot reach anything that borrows
/// a credential, and cannot cause an outbound model request whatever the
/// deployment is configured for.
/// </summary>
public sealed class PublicScannerTests(PublicScannerApiFactory factory)
    : IClassFixture<PublicScannerApiFactory>
{
    private const string Workflow = """
        name: Build
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
        """;

    private HttpClient Anonymous() => factory.CreateClient();

    private HttpClient WithKey()
    {
        HttpClient client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(
            "X-API-Key",
            PublicScannerApiFactory.ValidApiKey);
        return client;
    }

    [Theory]
    [InlineData("/api/rules")]
    [InlineData("/api/scenarios")]
    [InlineData("/api/ai/status")]
    [InlineData("/api/health/ready")]
    [InlineData("/api/security/status")]
    public async Task Anonymous_callers_reach_the_deterministic_surface(string path)
    {
        HttpResponseMessage response = await Anonymous().GetAsync(path);

        Assert.NotEqual(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Anonymous_callers_can_analyse_a_workflow()
    {
        HttpResponseMessage response = await Anonymous().PostAsJsonAsync(
            "/api/workflows/analyze",
            new { fileName = "build.yml", content = Workflow });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        string body = await response.Content.ReadAsStringAsync();

        // GHA001: actions/checkout@v4 is a tag, not a commit.
        Assert.Contains("GHA001", body, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("/api/github/status")]
    [InlineData("/api/github/repositories")]
    public async Task Anonymous_callers_cannot_reach_github(string path)
    {
        // Not because the data is sensitive, but because serving it spends the
        // App's private key on behalf of someone unidentified.
        HttpResponseMessage response = await Anonymous().GetAsync(path);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Anonymous_explanations_are_mock_even_though_the_server_is_configured_otherwise()
    {
        // The deployment is configured Live. This is the whole point of the
        // mode: an unidentified caller cannot cause an outbound request, so
        // cannot spend anything, and is told plainly what they received.
        HttpResponseMessage response = await Anonymous().PostAsJsonAsync(
            "/api/workflows/explain",
            new { fileName = "build.yml", content = Workflow, useAi = true });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        JsonElement explanation = await ReadExplanationAsync(response);

        Assert.Equal("Mock", explanation.GetProperty("mode").GetString());
        Assert.False(explanation.GetProperty("generatedByAi").GetBoolean());
        Assert.DoesNotContain(
            PublicScannerApiFactory.ConfiguredProviderMode,
            explanation.ToString(),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Identified_callers_get_the_configured_provider()
    {
        HttpResponseMessage response = await WithKey().PostAsJsonAsync(
            "/api/workflows/explain",
            new { fileName = "build.yml", content = Workflow, useAi = true });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        JsonElement explanation = await ReadExplanationAsync(response);

        Assert.Equal(
            PublicScannerApiFactory.ConfiguredProviderMode,
            explanation.GetProperty("mode").GetString());
    }

    [Fact]
    public async Task The_status_endpoint_says_a_key_is_not_needed_to_enter()
    {
        // The client renders its access gate from this. Reporting `required` in
        // Public mode would put a wall in front of a scanner that has nothing
        // to protect.
        HttpResponseMessage response =
            await Anonymous().GetAsync("/api/security/status");

        JsonElement status = JsonSerializer.Deserialize<JsonElement>(
            await response.Content.ReadAsStringAsync());

        Assert.False(status.GetProperty("required").GetBoolean());
        Assert.Equal("Public", status.GetProperty("mode").GetString());
        Assert.True(status.GetProperty("keyUnlocksGitHub").GetBoolean());
        Assert.True(status.GetProperty("keyUnlocksLiveAi").GetBoolean());
    }

    [Fact]
    public async Task An_invalid_key_does_not_promote_a_caller()
    {
        HttpClient client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-API-Key", new string('x', 48));

        HttpResponseMessage response = await client.PostAsJsonAsync(
            "/api/workflows/explain",
            new { fileName = "build.yml", content = Workflow, useAi = true });

        // Served, because the endpoint is open - but as an anonymous caller.
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        JsonElement explanation = await ReadExplanationAsync(response);

        Assert.Equal("Mock", explanation.GetProperty("mode").GetString());
    }

    [Fact]
    public async Task An_invalid_key_is_still_refused_at_a_privileged_endpoint()
    {
        HttpClient client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-API-Key", new string('x', 48));

        HttpResponseMessage response =
            await client.GetAsync("/api/github/status");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private static async Task<JsonElement> ReadExplanationAsync(
        HttpResponseMessage response)
    {
        JsonElement root = JsonSerializer.Deserialize<JsonElement>(
            await response.Content.ReadAsStringAsync());

        return root.TryGetProperty("explanation", out JsonElement explanation)
            ? explanation
            : root;
    }
}
