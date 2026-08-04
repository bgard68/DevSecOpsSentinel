using System.Net;
using System.Net.Http.Json;

namespace DevSecOpsSentinel.Api.Integration.Tests;

public sealed class ApiEndpointTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task Root_and_health_return_success()
    {
        Assert.Equal(HttpStatusCode.OK, (await _client.GetAsync("/")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _client.GetAsync("/api/health")).StatusCode);
    }

    [Fact]
    public async Task OpenApi_and_scalar_return_success_in_development()
    {
        Assert.Equal(HttpStatusCode.OK, (await _client.GetAsync("/openapi/v1.json")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _client.GetAsync("/scalar")).StatusCode);
    }

    [Fact]
    public async Task Rules_and_scenarios_return_success()
    {
        Assert.Equal(HttpStatusCode.OK, (await _client.GetAsync("/api/rules")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _client.GetAsync("/api/scenarios")).StatusCode);
    }

    [Fact]
    public async Task Missing_scenario_returns_not_found()
    {
        HttpResponseMessage response = await _client.GetAsync("/api/scenarios/not-real");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Finding_severity_is_serialized_as_a_name_not_an_integer()
    {
        // The client filters and sorts findings by comparing this field to
        // severity names. An integer here renders an empty findings list and a
        // "Low" risk label on a workflow that contains high-severity findings.
        HttpResponseMessage response = await _client.PostAsJsonAsync(
            "/api/workflows/analyze",
            new
            {
                fileName = "build.yml",
                content = "name: Build\non:\n  push:\npermissions: write-all\n"
                    + "jobs:\n  build:\n    timeout-minutes: 15\n"
                    + "    runs-on: ubuntu-latest\n    steps:\n"
                    + "      - uses: actions/checkout@0000000000000000000000000000000000000000\n"
            });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        string body = await response.Content.ReadAsStringAsync();

        Assert.Contains("\"severity\":\"High\"", body, StringComparison.Ordinal);
        Assert.DoesNotContain("\"severity\":3", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Hardened_scenario_is_the_zero_findings_baseline()
    {
        // The product claim that the AI agrees with the deterministic engine
        // instead of inventing vulnerabilities rests on this scenario returning
        // nothing. A new rule that fires here breaks that demonstration, so the
        // baseline is asserted rather than assumed.
        ScenarioResponse? scenario = await _client
            .GetFromJsonAsync<ScenarioResponse>("/api/scenarios/hardened-workflow");

        Assert.NotNull(scenario);

        HttpResponseMessage response = await _client.PostAsJsonAsync(
            "/api/workflows/analyze",
            new { fileName = scenario!.FileName, content = scenario.Content });

        AnalysisResponse? analysis =
            await response.Content.ReadFromJsonAsync<AnalysisResponse>();

        Assert.NotNull(analysis);
        Assert.Empty(analysis!.Findings);
    }

    [Fact]
    public async Task Script_injection_scenario_isolates_the_new_rule()
    {
        // The bundled scenario is pinned, permission-scoped and timed out, so
        // GHA005 should be the only finding it produces. A malformed fixture
        // would otherwise degrade the demo without failing anything.
        ScenarioResponse? scenario = await _client
            .GetFromJsonAsync<ScenarioResponse>("/api/scenarios/script-injection");

        Assert.NotNull(scenario);

        HttpResponseMessage response = await _client.PostAsJsonAsync(
            "/api/workflows/analyze",
            new { fileName = scenario!.FileName, content = scenario.Content });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        AnalysisResponse? analysis =
            await response.Content.ReadFromJsonAsync<AnalysisResponse>();

        Assert.NotNull(analysis);
        string ruleId = Assert.Single(
            analysis!.Findings.Select(finding => finding.RuleId).Distinct());

        Assert.Equal("GHA005", ruleId);
        Assert.Equal("Critical", Assert.Single(analysis.Findings).Severity);
    }

    private sealed record ScenarioResponse(string FileName, string Content);

    private sealed record AnalysisResponse(FindingResponse[] Findings);

    private sealed record FindingResponse(string RuleId, string Severity);

    [Fact]
    public async Task Vulnerable_workflow_returns_findings()
    {
        var request = new
        {
            fileName = "build.yml",
            content = "name: Build\non:\n  push:\npermissions: write-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
        };

        HttpResponseMessage response = await _client.PostAsJsonAsync("/api/workflows/analyze", request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        string body = await response.Content.ReadAsStringAsync();
        Assert.Contains("GHA001", body);
        Assert.Contains("GHA002", body);
        Assert.Contains("GHA003", body);
    }

    [Fact]
    public async Task Empty_request_returns_bad_request()
    {
        HttpResponseMessage response = await _client.PostAsJsonAsync(
            "/api/workflows/analyze",
            new { fileName = "", content = "" });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }


    [Fact]
    public async Task Malformed_json_returns_bad_request_problem_details()
    {
        using var content = new StringContent(
            "{\"fileName\":",
            System.Text.Encoding.UTF8,
            "application/json");

        HttpResponseMessage response = await _client.PostAsync(
            "/api/workflows/analyze",
            content);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        string body = await response.Content.ReadAsStringAsync();
        Assert.Contains("Invalid request body", body);
        Assert.DoesNotContain("System.Text.Json", body);
    }

    [Fact]
    public async Task Malformed_workflow_returns_unprocessable_entity()
    {
        HttpResponseMessage response = await _client.PostAsJsonAsync(
            "/api/workflows/analyze",
            new { fileName = "bad.yml", content = "this is not yaml" });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
    }
    [Fact]
    public async Task Ai_status_uses_mock_mode_and_does_not_expose_api_key()
    {
        HttpResponseMessage response = await _client.GetAsync("/api/ai/status");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        AiStatusResponse? status = await response.Content.ReadFromJsonAsync<AiStatusResponse>();
        Assert.NotNull(status);
        Assert.True(status.Enabled);
        Assert.False(status.Configured);
        Assert.Equal("OpenAI", status.Provider);
        Assert.Equal("Mock", status.Mode);
        Assert.Equal("gpt-5-mini", status.Model);

        string body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("apiKey", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("sk-", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Explanation_endpoint_returns_mock_explanation()
    {
        var request = new
        {
            fileName = "build.yml",
            content = "name: Build\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
            useAi = true
        };

        HttpResponseMessage response = await _client.PostAsJsonAsync("/api/workflows/explain", request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        string body = await response.Content.ReadAsStringAsync();
        Assert.Contains("Mock", body);
        Assert.Contains("GHA001", body);
    }

    [Fact]
    public async Task GitHub_status_is_safe_when_integration_is_disabled()
    {
        HttpResponseMessage response = await _client.GetAsync("/api/github/status");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        string body = await response.Content.ReadAsStringAsync();
        Assert.Contains("ReadOnly", body);
        Assert.DoesNotContain("privateKey", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("installationToken", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Non_allowlisted_GitHub_repository_is_forbidden()
    {
        HttpResponseMessage response = await _client.GetAsync(
            "/api/github/repositories/bgard68/ToDoApp/workflows");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Remediation_endpoint_returns_risk_reduction_and_diff()
    {
        var request = new
        {
            fileName = "build.yml",
            content = """
            name: Build
            on:
              push:
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
            """
        };

        HttpResponseMessage response = await _client.PostAsJsonAsync("/api/workflows/remediation", request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        string body = await response.Content.ReadAsStringAsync();
        Assert.Contains("riskReductionPercent", body);
        Assert.Contains("unifiedDiff", body);
        Assert.Contains("@@ -1,", body);
        Assert.Contains("GHA001", body);
    }

    [Fact]
    public async Task Sarif_export_is_available()
    {
        var request = new
        {
            fileName = "build.yml",
            content = """
            name: Build
            on:
              push:
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
            """
        };

        HttpResponseMessage response = await _client.PostAsJsonAsync("/api/workflows/remediation/export/sarif", request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        string body = await response.Content.ReadAsStringAsync();
        Assert.Contains("2.1.0", body);
        Assert.Contains("DevSecOps Sentinel", body);
    }

    [Fact]
    public async Task Operational_health_endpoints_return_success()
    {
        Assert.Equal(HttpStatusCode.OK, (await _client.GetAsync("/api/health/live")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _client.GetAsync("/api/health/ready")).StatusCode);
    }

    [Fact]
    public async Task Responses_include_correlation_and_security_headers()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/health");
        request.Headers.Add("X-Correlation-ID", "phase-f-test");
        HttpResponseMessage response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.TryGetValues("X-Correlation-ID", out var correlationValues));
        Assert.Contains("phase-f-test", correlationValues!);
        Assert.True(response.Headers.Contains("X-Content-Type-Options"));
        Assert.True(response.Headers.Contains("X-Frame-Options"));
        Assert.True(response.Headers.Contains("Content-Security-Policy"));
    }

    private sealed record AiStatusResponse(
        bool Enabled,
        bool Configured,
        string Provider,
        string Mode,
        string Model);

}
