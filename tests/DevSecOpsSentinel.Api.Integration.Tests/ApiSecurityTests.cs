using DevSecOpsSentinel.Api.Security;
using System.Net;
using System.Net.Http.Json;

namespace DevSecOpsSentinel.Api.Integration.Tests;

public sealed class ApiSecurityTests(
    RequiredSecurityApiFactory factory)
    : IClassFixture<RequiredSecurityApiFactory>
{
    private readonly HttpClient _client =
        factory.CreateClient();

    [Theory]
    [InlineData("/")]
    [InlineData("/api/health")]
    [InlineData("/api/health/live")]
    [InlineData("/api/health/ready")]
    [InlineData("/api/security/status")]
    [InlineData("/openapi/v1.json")]
    [InlineData("/scalar")]
    public async Task Public_endpoints_do_not_require_api_key(
        string path)
    {
        HttpResponseMessage response =
            await _client.GetAsync(path);

        Assert.NotEqual(
            HttpStatusCode.Unauthorized,
            response.StatusCode);
    }

    [Fact]
    public async Task Protected_endpoint_rejects_missing_api_key()
    {
        HttpResponseMessage response =
            await _client.GetAsync("/api/rules");

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            response.StatusCode);

        Assert.Equal(
            "application/problem+json",
            response.Content.Headers.ContentType?.MediaType);

        string body =
            await response.Content.ReadAsStringAsync();

        Assert.DoesNotContain(
            RequiredSecurityApiFactory.ValidApiKey,
            body,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Protected_endpoint_rejects_invalid_api_key()
    {
        using HttpRequestMessage request =
            new(HttpMethod.Get, "/api/rules");

        request.Headers.Add(
            "X-API-Key",
            "invalid-api-key");

        HttpResponseMessage response =
            await _client.SendAsync(request);

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            response.StatusCode);
    }

    [Fact]
    public async Task Protected_endpoint_accepts_valid_api_key()
    {
        using HttpRequestMessage request =
            new(HttpMethod.Get, "/api/rules");

        request.Headers.Add(
            "X-API-Key",
            RequiredSecurityApiFactory.ValidApiKey);

        HttpResponseMessage response =
            await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Workflow_analysis_requires_valid_api_key()
    {
        var payload = new
        {
            fileName = "build.yml",
            content = """
            name: Build
            on:
              push:
            jobs:
              build:
                timeout-minutes: 15
                runs-on: ubuntu-latest
            """
        };

        HttpResponseMessage unauthorized =
            await _client.PostAsJsonAsync(
                "/api/workflows/analyze",
                payload);

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            unauthorized.StatusCode);

        using HttpRequestMessage request =
            new(
                HttpMethod.Post,
                "/api/workflows/analyze")
            {
                Content = JsonContent.Create(payload)
            };

        request.Headers.Add(
            "X-API-Key",
            RequiredSecurityApiFactory.ValidApiKey);

        HttpResponseMessage authorized =
            await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, authorized.StatusCode);
    }

    [Fact]
    public void Disabled_security_is_rejected_outside_development_and_testing()
    {
        ApiSecurityOptions options = new()
        {
            Mode = ApiSecurityOptions.DisabledMode
        };

        Assert.True(options.IsValidForEnvironment("Development"));
        Assert.True(options.IsValidForEnvironment("Testing"));
        Assert.False(options.IsValidForEnvironment("Staging"));
        Assert.False(options.IsValidForEnvironment("Demo"));
        Assert.False(options.IsValidForEnvironment("Production"));
    }

}
