using System.Net;
using System.Net.Http.Json;

namespace DevSecOpsSentinel.Api.Integration.Tests;

/// <summary>
/// Rejection paths the API advertises but nothing exercised: 413, 429 and 503.
/// Each is declared on an endpoint or produced by a handler, so an unnoticed
/// regression would turn a documented refusal into a success or a 500.
/// </summary>
public sealed class FailurePathTests(ApiFactory factory)
    : IClassFixture<ApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task Oversized_workflow_returns_payload_too_large()
    {
        // The handler rejects above 100,000 characters. Kestrel's body limit is
        // 256 KiB, so this reaches the handler rather than being cut off by the
        // server, which is what makes it a 413 from the application.
        string oversized = new('x', 100_001);

        HttpResponseMessage response = await _client.PostAsJsonAsync(
            "/api/workflows/analyze",
            new { fileName = "build.yml", content = oversized });

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);

        Assert.Equal(
            "application/problem+json",
            response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task Workflow_just_under_the_limit_is_still_accepted()
    {
        // Guards the boundary from the other side, so a future off-by-one that
        // rejects valid input is not mistaken for the rule above working.
        string content =
            "name: Build\non:\n  push:\npermissions:\n  contents: read\n"
            + "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
            + "    timeout-minutes: 15\n";

        content += new string('#', 100_000 - content.Length);

        HttpResponseMessage response = await _client.PostAsJsonAsync(
            "/api/workflows/analyze",
            new { fileName = "build.yml", content });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task GitHub_repositories_report_unavailable_when_unconfigured()
    {
        // GitHub is disabled in this configuration, so the endpoint must say the
        // integration is unavailable rather than returning an empty list, which
        // would read as "no repositories" instead of "not configured".
        HttpResponseMessage response =
            await _client.GetAsync("/api/github/repositories");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }
}

/// <summary>
/// Rate limiting runs against its own host, because the window is shared across
/// every request the host serves and a two-request budget would starve the rest
/// of the suite.
/// </summary>
public sealed class RateLimitTests(RateLimitedApiFactory factory)
    : IClassFixture<RateLimitedApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task Analysis_beyond_the_permitted_rate_is_rejected()
    {
        object payload = new
        {
            fileName = "build.yml",
            content =
                "name: Build\non:\n  push:\npermissions:\n  contents: read\n"
                + "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
                + "    timeout-minutes: 15\n"
        };

        List<HttpStatusCode> observed = [];

        for (int attempt = 0; attempt < RateLimitedApiFactory.PermitLimit + 1; attempt++)
        {
            HttpResponseMessage response = await _client.PostAsJsonAsync(
                "/api/workflows/analyze",
                payload);

            observed.Add(response.StatusCode);
        }

        Assert.Equal(
            RateLimitedApiFactory.PermitLimit,
            observed.Count(status => status == HttpStatusCode.OK));

        Assert.Equal(HttpStatusCode.TooManyRequests, observed[^1]);
    }
}
