using DevSecOpsSentinel.Api.Operational;
using DevSecOpsSentinel.Api.Security;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace DevSecOpsSentinel.Api.Integration.Tests;

/// <summary>
/// Unit tests for the CORS policy provider. The policy is rebuilt per request
/// from the options monitor, so a configuration that lists no origins has to
/// produce a policy that permits none — not one that permits all.
/// </summary>
public sealed class DynamicCorsPolicyProviderTests
{
    private static Task<CorsPolicy?> Policy(
        ApiSecurityOptions options,
        string? policyName = "frontend") =>
        new DynamicCorsPolicyProvider(new StaticOptionsMonitor<ApiSecurityOptions>(options))
            .GetPolicyAsync(new DefaultHttpContext(), policyName);

    [Fact]
    public async Task GetPolicyAsync_FrontendPolicyWithConfiguredOrigins_AllowsExactlyThoseOriginsMethodsAndHeaders()
    {
        // Arrange
        ApiSecurityOptions options = new()
        {
            Mode = "Public",
            HeaderName = "X-API-Key",
            AllowedOrigins = ["https://app.example.com", "https://admin.example.com"]
        };

        // Act
        CorsPolicy policy = (await Policy(options))!;

        // Assert
        Assert.Equal(
            ["https://app.example.com", "https://admin.example.com"],
            policy.Origins);
        Assert.Equal(["GET", "POST"], policy.Methods);
        Assert.Equal(
            ["Content-Type", "X-API-Key", "X-Correlation-ID"],
            policy.Headers);
        Assert.False(policy.AllowAnyOrigin);
        Assert.False(policy.AllowAnyMethod);
        Assert.False(policy.AllowAnyHeader);
    }

    [Fact]
    public async Task GetPolicyAsync_CustomHeaderNameConfigured_AllowsThatHeaderInsteadOfTheDefault()
    {
        // Arrange. The allowed-header list has to track the configured header
        // name, or a browser preflight rejects the very key the API demands.
        ApiSecurityOptions options = new()
        {
            HeaderName = "X-Sentinel-Token",
            AllowedOrigins = ["https://app.example.com"]
        };

        // Act
        CorsPolicy policy = (await Policy(options))!;

        // Assert
        Assert.Contains("X-Sentinel-Token", policy.Headers);
        Assert.DoesNotContain("X-API-Key", policy.Headers);
    }

    [Fact]
    public async Task GetPolicyAsync_NoOriginsConfigured_ReturnsAPolicyThatPermitsNothing()
    {
        // Arrange. This is the case that matters. An empty allowlist must not
        // fall back to a wildcard, which is what a browser would then honour
        // from any site on the internet.
        ApiSecurityOptions options = new() { AllowedOrigins = [] };

        // Act
        CorsPolicy policy = (await Policy(options))!;

        // Assert
        Assert.Empty(policy.Origins);
        Assert.Empty(policy.Methods);
        Assert.Empty(policy.Headers);
        Assert.False(policy.AllowAnyOrigin);
        Assert.False(policy.AllowAnyMethod);
        Assert.False(policy.AllowAnyHeader);
    }

    [Theory]
    [InlineData("Frontend")]
    [InlineData("FRONTEND")]
    [InlineData("default")]
    [InlineData("")]
    public async Task GetPolicyAsync_PolicyNameIsNotTheExactFrontendName_ReturnsNull(string policyName)
    {
        // Arrange. The name is matched ordinally, so a differently-cased request
        // is a different policy and must not inherit the frontend allowances.
        ApiSecurityOptions options = new()
        {
            AllowedOrigins = ["https://app.example.com"]
        };

        // Act
        CorsPolicy? policy = await Policy(options, policyName);

        // Assert
        Assert.Null(policy);
    }

    [Fact]
    public async Task GetPolicyAsync_PolicyNameIsNull_ReturnsNull()
    {
        // Arrange
        ApiSecurityOptions options = new()
        {
            AllowedOrigins = ["https://app.example.com"]
        };

        // Act
        CorsPolicy? policy = await Policy(options, policyName: null);

        // Assert
        Assert.Null(policy);
    }
}

/// <summary>
/// Unit tests for the request timing log. Its one hard requirement is that the
/// record is emitted whatever the request did, including throwing.
/// </summary>
public sealed class RequestTelemetryMiddlewareTests
{
    private static DefaultHttpContext Context(string method, string path, int statusCode)
    {
        DefaultHttpContext context = new();
        context.Request.Method = method;
        context.Request.Path = path;
        context.Response.StatusCode = statusCode;
        return context;
    }

    [Fact]
    public async Task InvokeAsync_RequestSucceeds_LogsTheMethodPathAndStatusAtInformation()
    {
        // Arrange
        CapturingLogger<RequestTelemetryMiddleware> logger = new();
        DefaultHttpContext context = Context("GET", "/api/health", StatusCodes.Status200OK);

        RequestTelemetryMiddleware middleware = new(_ => Task.CompletedTask, logger);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        LogEntry entry = Assert.Single(logger.Entries);

        Assert.Equal(LogLevel.Information, entry.Level);
        Assert.StartsWith("HTTP GET /api/health returned 200 in ", entry.Message, StringComparison.Ordinal);
        Assert.EndsWith(" ms", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task InvokeAsync_DownstreamThrows_StillLogsAndRethrowsTheOriginalException()
    {
        // Arrange. The timing record lives in a finally block precisely so a
        // failed request is not the one that goes unrecorded.
        CapturingLogger<RequestTelemetryMiddleware> logger = new();
        DefaultHttpContext context = Context("POST", "/api/workflows/analyze", StatusCodes.Status500InternalServerError);
        InvalidOperationException expected = new("downstream failed");

        RequestTelemetryMiddleware middleware = new(_ => throw expected, logger);

        // Act
        InvalidOperationException actual = await Assert.ThrowsAsync<InvalidOperationException>(
            () => middleware.InvokeAsync(context));

        // Assert
        Assert.Same(expected, actual);

        LogEntry entry = Assert.Single(logger.Entries);
        Assert.StartsWith(
            "HTTP POST /api/workflows/analyze returned 500 in ",
            entry.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task InvokeAsync_RequestMethodCarriesANewline_ReplacesItWithTheSubstituteCharacter()
    {
        // Arrange. Method reaches the log as a plain string, so it is the field
        // that actually carries an injection through. LogSanitizer substitutes
        // control characters rather than dropping them, so the attempt stays
        // visible in the record instead of vanishing from it.
        CapturingLogger<RequestTelemetryMiddleware> logger = new();
        DefaultHttpContext context = Context(
            "GET\nHTTP GET /forged returned 200",
            "/api/health",
            StatusCodes.Status404NotFound);

        RequestTelemetryMiddleware middleware = new(_ => Task.CompletedTask, logger);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        LogEntry entry = Assert.Single(logger.Entries);

        Assert.DoesNotContain('\n', entry.Message);
        Assert.DoesNotContain('\r', entry.Message);
        Assert.StartsWith(
            "HTTP GET�HTTP GET /forged returned 200 /api/health returned 404 in ",
            entry.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task InvokeAsync_RequestPathCarriesANewline_PercentEncodesItOntoASingleLine()
    {
        // Arrange. Path reaches the log through PathString, whose ToString
        // percent-encodes, so the newline is already gone before LogSanitizer
        // sees it. Asserting the substitute character here would be asserting a
        // behaviour this field does not have; the guarantee that holds is that
        // the record stays on one line.
        CapturingLogger<RequestTelemetryMiddleware> logger = new();
        DefaultHttpContext context = Context(
            "GET",
            "/api/health\nHTTP GET /forged returned 200",
            StatusCodes.Status404NotFound);

        RequestTelemetryMiddleware middleware = new(_ => Task.CompletedTask, logger);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        LogEntry entry = Assert.Single(logger.Entries);

        Assert.DoesNotContain('\n', entry.Message);
        Assert.DoesNotContain('\r', entry.Message);
        Assert.StartsWith(
            "HTTP GET /api/health%0AHTTP%20GET%20/forged%20returned%20200 returned 404 in ",
            entry.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task InvokeAsync_RequestPathIsLongerThanTheLogLimit_TruncatesItWithAnEllipsis()
    {
        // Arrange. Truncation is what LogSanitizer contributes on a field that
        // PathString has already encoded: without it a single request can flood
        // the log with an arbitrarily long path.
        CapturingLogger<RequestTelemetryMiddleware> logger = new();
        string longPath = "/" + new string('a', 600);
        DefaultHttpContext context = Context("GET", longPath, StatusCodes.Status404NotFound);

        RequestTelemetryMiddleware middleware = new(_ => Task.CompletedTask, logger);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        LogEntry entry = Assert.Single(logger.Entries);

        Assert.StartsWith(
            $"HTTP GET {longPath[..512]}… returned 404 in ",
            entry.Message,
            StringComparison.Ordinal);
        Assert.DoesNotContain(longPath, entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task InvokeAsync_DownstreamSetsTheStatusCode_LogsTheFinalCodeNotTheInitialOne()
    {
        // Arrange. The status is read after next() returns, so a handler that
        // sets 404 late must not be recorded as the default 200.
        CapturingLogger<RequestTelemetryMiddleware> logger = new();
        DefaultHttpContext context = Context("GET", "/api/scenarios/missing", StatusCodes.Status200OK);

        RequestTelemetryMiddleware middleware = new(
            ctx =>
            {
                ctx.Response.StatusCode = StatusCodes.Status404NotFound;
                return Task.CompletedTask;
            },
            logger);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        Assert.StartsWith(
            "HTTP GET /api/scenarios/missing returned 404 in ",
            Assert.Single(logger.Entries).Message,
            StringComparison.Ordinal);
    }
}
