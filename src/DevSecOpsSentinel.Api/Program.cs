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
using DevSecOpsSentinel.Infrastructure.Rules.Fixes;
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
// The repairs, composed from the same single list the tests and the eval read. Stated as a
// factory rather than by type so the constructor taking the fix set is the one selected, and
// so a reader of this file can see that the patch generator is handed its repairs rather
// than containing them.
builder.Services.AddSingleton<IWorkflowPatchGenerator>(services =>
    new WorkflowPatchGenerator(
        services.GetRequiredService<IWorkflowParser>(),
        services.GetServices<IWorkflowSecurityRule>(),
        FixDiscovery.All(
            services.GetRequiredService<IWorkflowActionReferenceResolver>(),
            services.GetRequiredService<GitHubOptions>())));
builder.Services.AddSingleton<IWorkflowAnalysisService, WorkflowAnalysisService>();
builder.Services.AddSingleton<IRemediationReportService, RemediationReportService>();

builder.Services.AddSingleton<IScenarioStore>(
    _ => new FileScenarioStore(scenarioDirectory));

builder.Services.AddSingleton<
    ISensitiveDataSanitizer,
    SensitiveDataSanitizer>();

/*
 * Bound, validated and checked on start, matching the API security options above.
 *
 * These two sections were previously read with Get<T>() into a plain singleton, which meant
 * no validation ran over them and a wrong value surfaced as a failed request rather than a
 * refusal to start. The singleton registration is kept so the options stay directly
 * injectable — endpoints and infrastructure take OpenAiOptions and GitHubOptions, not
 * IOptions<T>, because nothing here reloads them and the indirection would buy nothing.
 */
builder.Services
    .AddOptions<OpenAiOptions>()
    .Bind(builder.Configuration.GetSection(OpenAiOptions.SectionName))
    .ValidateOnStart();

builder.Services.AddSingleton<
    IValidateOptions<OpenAiOptions>,
    OpenAiOptionsValidator>();

builder.Services.AddSingleton(services =>
    services.GetRequiredService<IOptions<OpenAiOptions>>().Value);

// Selection lives in the factory, where it can be tested without a web host and where an
// unrecognised mode is reported rather than quietly treated as Mock.
builder.Services.AddSingleton<IWorkflowAiProvider>(services =>
    WorkflowAiProviderFactory.Create(
        services.GetRequiredService<OpenAiOptions>(),
        services.GetRequiredService<ILoggerFactory>()));

// Registered separately from the configured provider so the selector can hand
// it to anonymous callers whatever the deployment is set to.
builder.Services.AddSingleton<MockWorkflowAiProvider>();
builder.Services.AddSingleton<
    IWorkflowAiProviderSelector,
    WorkflowAiProviderSelector>();

builder.Services.AddSingleton<
    IWorkflowExplanationService,
    WorkflowExplanationService>();

builder.Services
    .AddOptions<GitHubOptions>()
    .Bind(builder.Configuration.GetSection(GitHubOptions.SectionName))
    .ValidateOnStart();

builder.Services.AddSingleton<
    IValidateOptions<GitHubOptions>,
    GitHubOptionsValidator>();

builder.Services.AddSingleton(services =>
    services.GetRequiredService<IOptions<GitHubOptions>>().Value);
builder.Services.AddHttpClient("GitHub", client =>
{
    client.Timeout = TimeSpan.FromSeconds(30);
});

// The anonymous public-repository scanner. A separate named client from "GitHub" on
// purpose: that one carries an installation token, this one must never carry anything.
// GitHub rejects requests without a User-Agent, and asking for the JSON media type keeps
// the contents API's answers stable.
builder.Services.AddHttpClient("GitHubPublic", client =>
{
    client.BaseAddress = new Uri("https://api.github.com");
    client.Timeout = TimeSpan.FromSeconds(30);
    client.DefaultRequestHeaders.UserAgent.ParseAdd("DevSecOpsSentinel");
    client.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
});

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<IPublicRepositoryScanner, PublicRepositoryScanner>();

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

    /*
     * An unrecognised AI mode resolves to Mock rather than refusing to start, for the reason
     * given in WorkflowAiModes. Reported here as well as by the factory because the provider
     * is built on first use: without this, a deployment configured for live explanations and
     * silently mocked would say nothing until someone requested one.
     */
    OpenAiOptions startupAi = app.Services.GetRequiredService<OpenAiOptions>();

    if (!WorkflowAiModes.TryParse(startupAi.Mode, out WorkflowAiMode _))
    {
        startupLogger.LogWarning(
            "OpenAI:Mode is {ConfiguredMode}, which is not a recognised mode. AI "
            + "explanations will be mocked and reported as {ResolvedMode}. Recognised "
            + "modes are {RecognisedModes}.",
            string.IsNullOrWhiteSpace(startupAi.Mode) ? "empty" : startupAi.Mode,
            startupAi.ResolvedModeName,
            string.Join(", ", Enum.GetNames<WorkflowAiMode>()));
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

app.MapStatusEndpoints()
   .MapGitHubEndpoints()
   .MapCatalogueEndpoints()
   .MapPublicScanEndpoints()
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
