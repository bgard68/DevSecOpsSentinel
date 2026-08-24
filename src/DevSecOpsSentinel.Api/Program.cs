using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using DevSecOpsSentinel.Api;
using DevSecOpsSentinel.Api.Endpoints;
using DevSecOpsSentinel.Api.Operational;
using DevSecOpsSentinel.Api.Security;
using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;
using DevSecOpsSentinel.Infrastructure;
using DevSecOpsSentinel.Infrastructure.Ai;
using DevSecOpsSentinel.Infrastructure.GitHub;
using DevSecOpsSentinel.Infrastructure.Rules;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using Scalar.AspNetCore;

const int maximumWorkflowCharacters = 100_000;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = 256 * 1024;
});

/*
 * WorkflowSeverity is a domain enum. Without this converter System.Text.Json
 * emits its integer value, so the API returned "severity": 3 while the React
 * client, the JSON export and every other consumer expect "High". The client
 * filters and sorts findings by comparing that field to severity names, so the
 * numeric form silently produced an empty findings list and a "Low" risk label
 * on workflows that in fact contained high-severity findings.
 */
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.Converters.Add(
        new JsonStringEnumConverter());
});

builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<ApiExceptionHandler>();
builder.Services.AddOpenApi();
builder.Services.AddOutputCache();
builder.Services.AddMemoryCache();

builder.Services
    .AddOptions<ApiSecurityOptions>()
    .Bind(
        builder.Configuration.GetSection(
            ApiSecurityOptions.SectionName))
    .Validate(
        options =>
            options.IsValidForEnvironment(
                builder.Environment.EnvironmentName),
        "API authentication must be Required outside Development/Testing, and required keys must contain at least 32 characters.")
    .ValidateOnStart();

builder.Services.AddCors();
builder.Services.AddSingleton<
    ICorsPolicyProvider,
    DynamicCorsPolicyProvider>();

builder.Services
    .AddOptions<OperationalOptions>()
    .Bind(builder.Configuration.GetSection(OperationalOptions.SectionName));

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode =
        StatusCodes.Status429TooManyRequests;

    // Both budgets are read from the request's own service provider rather than
    // captured here. Reading them during startup froze the limit at whatever the
    // base configuration said, so the documented setting could not actually be
    // changed by a host that supplies configuration later.
    options.AddPolicy(
        "github-read",
        httpContext => CreatePartition(
            httpContext,
            operational => operational.GitHubReadLimitPerMinute));

    options.AddPolicy(
        "workflow-analysis",
        httpContext => CreatePartition(
            httpContext,
            operational => operational.WorkflowRequestLimitPerMinute));
});

builder.Services.Configure<FormOptions>(options =>
{
    options.ValueLengthLimit = maximumWorkflowCharacters;
});

/*
 * Minimal API request-body binding normally returns an empty 400 response
 * when malformed JSON is received.
 *
 * ThrowOnBadRequest forces the binding failure to throw a
 * BadHttpRequestException so ApiExceptionHandler can return RFC 7807
 * Problem Details with application/problem+json.
 */
builder.Services.Configure<RouteHandlerOptions>(options =>
{
    options.ThrowOnBadRequest = true;
});

string scenarioDirectory = Path.Combine(
    AppContext.BaseDirectory,
    "Scenarios");

builder.Services.AddSingleton<IWorkflowParser, WorkflowParser>();
// Discovered, not listed. A rule added to Infrastructure and forgotten here would never
// run, and nothing would report it — the failure is silence, which is why this is not a
// hand-maintained list. RuleDiscovery is the single source the tests and the eval use too.
foreach (IWorkflowSecurityRule rule in RuleDiscovery.All())
{
    builder.Services.AddSingleton(rule);
}
builder.Services.AddSingleton<IWorkflowPatchGenerator, WorkflowPatchGenerator>();
builder.Services.AddSingleton<IWorkflowAnalysisService, WorkflowAnalysisService>();
builder.Services.AddSingleton<IRemediationReportService, RemediationReportService>();

builder.Services.AddSingleton<IScenarioStore>(
    _ => new FileScenarioStore(scenarioDirectory));

builder.Services.AddSingleton<
    ISensitiveDataSanitizer,
    SensitiveDataSanitizer>();

OpenAiOptions openAiOptions = builder.Configuration
    .GetSection(OpenAiOptions.SectionName)
    .Get<OpenAiOptions>()
    ?? new OpenAiOptions();

builder.Services.AddSingleton(openAiOptions);

builder.Services.AddSingleton<IWorkflowAiProvider>(services =>
    openAiOptions.Mode.ToUpperInvariant() switch
    {
        "LIVE" => new OpenAiWorkflowAiProvider(
            openAiOptions,
            services.GetRequiredService<
                ILogger<OpenAiWorkflowAiProvider>>()),
        "DISABLED" => new DisabledWorkflowAiProvider(),
        _ => new MockWorkflowAiProvider()
    });

// Registered separately from the configured provider so the selector can hand
// it to anonymous callers whatever the deployment is set to.
builder.Services.AddSingleton<MockWorkflowAiProvider>();
builder.Services.AddSingleton<
    IWorkflowAiProviderSelector,
    WorkflowAiProviderSelector>();

builder.Services.AddSingleton<
    IWorkflowExplanationService,
    WorkflowExplanationService>();

GitHubOptions gitHubOptions = builder.Configuration
    .GetSection(GitHubOptions.SectionName)
    .Get<GitHubOptions>()
    ?? new GitHubOptions();

builder.Services.AddSingleton(gitHubOptions);
builder.Services.AddHttpClient("GitHub", client =>
{
    client.Timeout = TimeSpan.FromSeconds(30);
});

builder.Services.AddSingleton<
    IGitHubPrivateKeySource,
    GitHubPrivateKeySource>();

// Written by the API-key middleware, read by endpoints that behave differently
// for an identified caller. Scoped: it describes one request.
builder.Services.AddScoped<CallerAuthentication>();

builder.Services.AddSingleton<GitHubAppJwtFactory>();

builder.Services.AddSingleton<
    IGitHubInstallationTokenProvider,
    GitHubInstallationTokenProvider>();

builder.Services.AddSingleton<
    IGitHubRepositoryReader,
    GitHubRepositoryReader>();

builder.Services.AddSingleton<
    IWorkflowActionReferenceResolver,
    GitHubActionReferenceResolver>();

WebApplication app = builder.Build();

/*
 * AllowedHosts ships as localhost only, which is right for development and
 * silently wrong once deployed: host filtering rejects every request with a 400
 * and nothing in the response explains why. The symptom looks like a routing or
 * proxy fault rather than a setting.
 *
 * This warns rather than refuses to start. A wrong host is fixed by editing one
 * setting, whereas an application that will not start has to be diagnosed
 * through deployment logs — the worse of the two failures. The same applies to
 * CORS origins, which fail as blocked browser requests with a working API
 * behind them.
 */
if (!app.Environment.IsDevelopment() &&
    !app.Environment.IsEnvironment("Testing"))
{
    ILogger startupLogger = app.Services
        .GetRequiredService<ILoggerFactory>()
        .CreateLogger("DevSecOpsSentinel.Startup");

    string allowedHosts = app.Configuration["AllowedHosts"] ?? string.Empty;

    if (allowedHosts.Contains("localhost", StringComparison.OrdinalIgnoreCase) ||
        allowedHosts.Contains("127.0.0.1", StringComparison.Ordinal))
    {
        startupLogger.LogWarning(
            "AllowedHosts is {AllowedHosts} in the {Environment} environment. " +
            "Requests arriving on any other host will be rejected with 400 " +
            "before reaching a route.",
            allowedHosts,
            app.Environment.EnvironmentName);
    }

    ApiSecurityOptions startupSecurity = app.Services
        .GetRequiredService<IOptions<ApiSecurityOptions>>().Value;

    if (startupSecurity.AllowedOrigins.Length == 0 ||
        startupSecurity.AllowedOrigins.Any(origin =>
            origin.Contains("localhost", StringComparison.OrdinalIgnoreCase)))
    {
        startupLogger.LogWarning(
            "Security:AllowedOrigins is {Origins} in the {Environment} " +
            "environment. A browser client served from any other origin will be " +
            "blocked by CORS.",
            startupSecurity.AllowedOrigins.Length == 0
                ? "empty"
                : string.Join(", ", startupSecurity.AllowedOrigins),
            app.Environment.EnvironmentName);
    }
}

if (app.Environment.IsDevelopment() ||
    app.Environment.IsEnvironment("Testing"))
{
    app.MapOpenApi();

    app.MapScalarApiReference(options =>
    {
        options.WithTitle("DevSecOps Sentinel API");
    });
}

app.UseExceptionHandler();

if (!app.Environment.IsDevelopment() &&
    !app.Environment.IsEnvironment("Testing"))
{
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseMiddleware<CorrelationIdMiddleware>();
app.UseMiddleware<RequestTelemetryMiddleware>();
app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseCors("frontend");
app.UseMiddleware<ApiKeyAuthenticationMiddleware>();
app.UseRateLimiter();
app.UseOutputCache();

app.MapStatusEndpoints(openAiOptions, gitHubOptions)
   .MapGitHubEndpoints(gitHubOptions)
   .MapCatalogueEndpoints()
   .MapWorkflowEndpoints(maximumWorkflowCharacters);

app.Run();

static RateLimitPartition<string> CreatePartition(
    HttpContext httpContext,
    Func<OperationalOptions, int> selectLimit)
{
    OperationalOptions operational = httpContext.RequestServices
        .GetRequiredService<IOptionsMonitor<OperationalOptions>>()
        .CurrentValue;

    string headerName = httpContext.RequestServices
        .GetRequiredService<IOptionsMonitor<ApiSecurityOptions>>()
        .CurrentValue
        .HeaderName;

    return RateLimitPartition.GetFixedWindowLimiter(
        GetRateLimitPartitionKey(httpContext, headerName),
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = Math.Max(1, selectLimit(operational)),
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            AutoReplenishment = true
        });
}

static string GetRateLimitPartitionKey(
    HttpContext context,
    string apiKeyHeaderName)
{
    string? apiKey =
        context.Request.Headers[apiKeyHeaderName].FirstOrDefault();

    if (!string.IsNullOrWhiteSpace(apiKey))
    {
        byte[] hash = SHA256.HashData(
            Encoding.UTF8.GetBytes(apiKey));

        return $"key:{Convert.ToHexString(hash)}";
    }

    return
        $"ip:{context.Connection.RemoteIpAddress?.ToString() ?? "unknown"}";
}

public partial class Program;
