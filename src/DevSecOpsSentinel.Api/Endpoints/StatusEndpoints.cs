using Microsoft.Extensions.Options;
using System.Text.Json;
using DevSecOpsSentinel.Api.Security;
using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;
using DevSecOpsSentinel.Infrastructure.Ai;
using DevSecOpsSentinel.Infrastructure.GitHub;
using Microsoft.AspNetCore.Mvc;

namespace DevSecOpsSentinel.Api.Endpoints;

/// <summary>
/// Root, health, security status, AI status.
/// Liveness and readiness are deliberately distinct: liveness answers as soon as the
/// process is listening, readiness only once the app can serve. A deploy that waited on
/// the wrong one ran its smoke test against a half-started app.
///
/// Extracted from Program.cs, which had grown to 944 lines holding the composition root,
/// the middleware pipeline and every handler body at once.
/// </summary>
public static class StatusEndpoints
{
    // Same rule as GitHubEndpoints: options resolve from DI at request time, not from a
    // pre-Build snapshot captured into the closure.
    public static WebApplication MapStatusEndpoints(this WebApplication app)
    {
    // GET *and* HEAD: uptime monitors and platform probes default to HEAD, and a status
    // endpoint that answers 405 to the probe watching it cannot report bad news.
    app.MapMethods("/", new[] { "GET", "HEAD" }, () => Results.Ok(new
    {
        status = "Running",
        application = ProductInfo.Name,
        version = ProductInfo.Version,
        message =
            "Open /scalar for API documentation or " +
            "http://localhost:5173 for the React application."
    }));

    app.MapGet("/api/health", () => Results.Ok(new
    {
        status = "Healthy",
        application = ProductInfo.Name,
        version = ProductInfo.Version
    }));

    app.MapGet(
        "/api/security/status",
        (IOptionsMonitor<ApiSecurityOptions> optionsMonitor) =>
        {
            ApiSecurityOptions security =
                optionsMonitor.CurrentValue;

            return Results.Ok(new
            {
                // Whether a key is needed to use the API at all. False in Public
                // mode, where the scanner is open and the key only unlocks more.
                required = security.IsRequired,
                headerName = security.HeaderName,
                sessionOnlyBrowserKey = true,
                mode = security.Mode,

                // So the client can offer the key as an upgrade rather than a gate,
                // and say what it is for.
                keyUnlocksGitHub = security.UsesApiKey,
                keyUnlocksLiveAi = security.UsesApiKey
            });
        });

    app.MapGet("/api/health/live", () => Results.Ok(new
    {
        status = "Healthy",
        check = "Liveness",
        timestampUtc = DateTimeOffset.UtcNow
    }))
    .CacheOutput(policy =>
        policy.Expire(TimeSpan.FromSeconds(10)));

    /*
     * Readiness answers one question: can this instance serve requests?
     *
     * Deterministic analysis is the product and depends on nothing external, so the
     * answer is yes whenever the process started. GitHub and OpenAI are optional
     * integrations, and reporting the whole application as unready because one of
     * them is misconfigured would take a working instance out of rotation over a
     * feature most requests never touch.
     *
     * Their state is reported here so a misconfiguration is visible, and separately
     * on /api/github/status and /api/ai/status, but a degraded integration does not
     * make the application unready. What it must never do is silently present
     * simulated results as real ones — an integration configured for live use and
     * unable to reach its service reports exactly that.
     */
    app.MapGet("/api/health/ready", (
        OpenAiOptions openAiOptions,
        GitHubOptions gitHubOptions,
        IGitHubPrivateKeySource privateKeySource) =>
    {
        bool gitHubDegraded =
            gitHubOptions.Enabled &&
            (!gitHubOptions.IsConfigured || !privateKeySource.IsAvailable);

        bool openAiDegraded =
            string.Equals(openAiOptions.Mode, "Live", StringComparison.OrdinalIgnoreCase) &&
            string.IsNullOrWhiteSpace(openAiOptions.ApiKey);

        return Results.Ok(new
        {
            status = "Ready",
            deterministicAnalysis = "Available",
            gitHub = new
            {
                state = !gitHubOptions.Enabled
                    ? "Disabled"
                    : gitHubDegraded ? "Unavailable" : "ReadOnly",
                detail = !gitHubOptions.Enabled
                    ? "GitHub integration is disabled."
                    : gitHubDegraded
                        ? "GitHub is enabled but its configuration or private key is incomplete."
                        : $"Connected using a private key supplied by {privateKeySource.Description}.",
            },
            ai = new
            {
                state = openAiDegraded ? "Unavailable" : openAiOptions.Mode,
                detail = openAiDegraded
                    ? "OpenAI is configured for live mode but no API key is available. Explanations fall back to deterministic text and are labelled as such."
                    : $"OpenAI is in {openAiOptions.Mode} mode."
            },
            timestampUtc = DateTimeOffset.UtcNow
        });
    });

    app.MapGet("/api/ai/status", (OpenAiOptions openAiOptions) =>
    {
        bool configured =
            !string.IsNullOrWhiteSpace(openAiOptions.ApiKey);

        return Results.Ok(new
        {
            enabled = !string.Equals(
                openAiOptions.Mode,
                "Disabled",
                StringComparison.OrdinalIgnoreCase),

            configured,
            provider = "OpenAI",
            mode = openAiOptions.Mode,
            model = openAiOptions.Model,

            costProtection = new
            {
                explicitRequestOnly = true,
                mockModeConsumesCredits = false
            }
        });
    });

        return app;
    }
}
