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

    [Fact]
    public void Public_security_is_accepted_in_production()
    {
        // Public is not a relaxation of Required - it is a different statement
        // about which endpoints need the key. Refusing it in Production would
        // have left Required as the only legal value, which is what made a
        // public deployment unusable by the public.
        ApiSecurityOptions options = new()
        {
            Mode = ApiSecurityOptions.PublicMode,
            ApiKey = new string('k', 32)
        };

        Assert.True(options.IsValidForEnvironment("Production"));
        Assert.True(options.IsValidForEnvironment("Staging"));
    }

    [Fact]
    public void Public_security_still_requires_a_usable_key()
    {
        // The key has not stopped mattering; it now guards a smaller surface.
        // Accepting Public without one would silently open GitHub too.
        ApiSecurityOptions options = new()
        {
            Mode = ApiSecurityOptions.PublicMode,
            ApiKey = "short"
        };

        Assert.False(options.IsValidForEnvironment("Production"));
        Assert.Contains(
            "at least 32 characters",
            options.GetValidationFailure("Production"),
            StringComparison.Ordinal);
    }

    [Fact]
    public void The_failure_message_names_both_legal_production_modes()
    {
        // The previous message said Required only, which would now send a
        // reader to the wrong fix.
        ApiSecurityOptions options = new()
        {
            Mode = ApiSecurityOptions.DisabledMode
        };

        string failure = options.GetValidationFailure("Production");

        Assert.Contains("Required", failure, StringComparison.Ordinal);
        Assert.Contains("Public", failure, StringComparison.Ordinal);
    }
}
