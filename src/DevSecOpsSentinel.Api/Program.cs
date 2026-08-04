using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using DevSecOpsSentinel.Api;
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
builder.Services.AddSingleton<IWorkflowSecurityRule, UnpinnedActionRule>();
builder.Services.AddSingleton<IWorkflowSecurityRule, ExcessivePermissionsRule>();
builder.Services.AddSingleton<IWorkflowSecurityRule, MissingTimeoutRule>();
builder.Services.AddSingleton<IWorkflowSecurityRule, UnsafePullRequestTargetRule>();
builder.Services.AddSingleton<IWorkflowSecurityRule, ScriptInjectionRule>();
builder.Services.AddSingleton<IWorkflowSecurityRule, PersistedCredentialsRule>();
builder.Services.AddSingleton<IWorkflowSecurityRule, UntrustedCheckoutRule>();
builder.Services.AddSingleton<IWorkflowSecurityRule, InheritedSecretsRule>();
builder.Services.AddSingleton<IWorkflowSecurityRule, UndeclaredPermissionsRule>();
builder.Services.AddSingleton<IWorkflowSecurityRule, SelfHostedRunnerRule>();
builder.Services.AddSingleton<IWorkflowSecurityRule, ArtifactPoisoningRule>();
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

app.MapGet("/", () => Results.Ok(new
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
            required = security.IsRequired,
            headerName = security.HeaderName,
            sessionOnlyBrowserKey = true
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
app.MapGet("/api/health/ready", (IGitHubPrivateKeySource privateKeySource) =>
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

app.MapGet("/api/ai/status", () =>
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

app.MapGet(
    "/api/github/status",
    async (
        IGitHubRepositoryReader reader,
        ILogger<Program> logger,
        CancellationToken cancellationToken) =>
    {
        if (!gitHubOptions.Enabled)
        {
            return Results.Ok(new GitHubConnectionStatus(
                false,
                false,
                false,
                "ReadOnly",
                gitHubOptions.AllowedRepositories.Length,
                "GitHub integration is disabled."));
        }

        if (!gitHubOptions.IsConfigured)
        {
            return Results.Ok(new GitHubConnectionStatus(
                true,
                false,
                false,
                "ReadOnly",
                gitHubOptions.AllowedRepositories.Length,
                "GitHub App configuration is incomplete."));
        }

        try
        {
            IReadOnlyList<GitHubRepositorySummary> repositories =
                await reader.GetRepositoriesAsync(cancellationToken);

            return Results.Ok(new GitHubConnectionStatus(
                true,
                true,
                true,
                "ReadOnly",
                repositories.Count,
                "Connected using a short-lived GitHub App " +
                "installation token."));
        }
        catch (Exception exception)
        {
            logger.LogWarning(
                exception,
                "GitHub status check failed.");

            return Results.Ok(new GitHubConnectionStatus(
                true,
                true,
                false,
                "ReadOnly",
                gitHubOptions.AllowedRepositories.Length,
                "GitHub could not be reached or authentication failed."));
        }
    });

app.MapGet(
    "/api/github/repositories",
    async (
        IGitHubRepositoryReader reader,
        CancellationToken cancellationToken) =>
    {
        if (!gitHubOptions.IsConfigured)
        {
            return Results.Problem(
                title: "GitHub integration is not configured",
                statusCode:
                    StatusCodes.Status503ServiceUnavailable);
        }

        return Results.Ok(
            await reader.GetRepositoriesAsync(cancellationToken));
    })
    .RequireRateLimiting("github-read");

app.MapGet(
    "/api/github/repositories/{owner}/{repository}/workflows",
    async (
        string owner,
        string repository,
        IGitHubRepositoryReader reader,
        CancellationToken cancellationToken) =>
    {
        if (!gitHubOptions.IsAllowed(owner, repository))
        {
            return Results.Problem(
                statusCode: StatusCodes.Status403Forbidden,
                title: "Repository access denied",
                detail:
                    "The requested repository is not included in " +
                    "the configured allowlist.");
        }

        return Results.Ok(
            await reader.GetWorkflowsAsync(
                owner,
                repository,
                cancellationToken));
    })
    .RequireRateLimiting("github-read");

app.MapGet(
    "/api/github/repositories/{owner}/{repository}/workflows/content",
    async (
        string owner,
        string repository,
        string path,
        string? reference,
        IGitHubRepositoryReader reader,
        CancellationToken cancellationToken) =>
    {
        if (!gitHubOptions.IsAllowed(owner, repository))
        {
            return Results.Problem(
                statusCode: StatusCodes.Status403Forbidden,
                title: "Repository access denied",
                detail:
                    "The requested repository is not included in " +
                    "the configured allowlist.");
        }

        GitHubWorkflowFile? workflow =
            await reader.GetWorkflowAsync(
                owner,
                repository,
                path,
                reference,
                cancellationToken);

        return workflow is null
            ? Results.NotFound()
            : Results.Ok(workflow);
    })
    .RequireRateLimiting("github-read");

app.MapPost(
    "/api/github/repositories/{owner}/{repository}/analyze",
    async (
        string owner,
        string repository,
        AnalyzeGitHubWorkflowRequest? request,
        IGitHubRepositoryReader reader,
        IWorkflowAnalysisService analysisService,
        IWorkflowExplanationService explanationService,
        CancellationToken cancellationToken) =>
    {
        if (!gitHubOptions.IsAllowed(owner, repository))
        {
            return Results.Problem(
                statusCode: StatusCodes.Status403Forbidden,
                title: "Repository access denied",
                detail:
                    "The requested repository is not included in " +
                    "the configured allowlist.");
        }

        if (request is null ||
            string.IsNullOrWhiteSpace(request.Path))
        {
            return Results.BadRequest(new ProblemDetails
            {
                Title = "Invalid GitHub workflow request",
                Detail = "A workflow path is required.",
                Status = StatusCodes.Status400BadRequest
            });
        }

        GitHubWorkflowFile? workflow =
            await reader.GetWorkflowAsync(
                owner,
                repository,
                request.Path,
                request.Reference,
                cancellationToken);

        if (workflow is null)
        {
            return Results.NotFound();
        }

        WorkflowDocument document = new(
            Path.GetFileName(workflow.Path),
            workflow.Content);

        if (request.UseAi)
        {
            WorkflowExplanationResult explained =
                await explanationService.ExplainAsync(
                    document,
                    true,
                    cancellationToken);

            return Results.Ok(new
            {
                source = workflow,
                result = explained
            });
        }

        WorkflowAnalysisResult analyzed =
            await analysisService.AnalyzeAsync(
                document,
                cancellationToken);

        return Results.Ok(new
        {
            source = workflow,
            result = analyzed
        });
    })
    .RequireRateLimiting("workflow-analysis");

app.MapGet(
    "/api/rules",
    (IEnumerable<IWorkflowSecurityRule> rules) =>
        Results.Ok(
            rules.Select(rule => new
            {
                rule.RuleId,
                rule.Title,
                severity = rule.Severity.ToString()
            })
            .OrderBy(rule => rule.RuleId)))
    .CacheOutput(policy =>
        policy.Expire(TimeSpan.FromMinutes(5)));

app.MapGet(
    "/api/scenarios",
    (IScenarioStore store) =>
        Results.Ok(store.GetAll()))
    .CacheOutput(policy =>
        policy.Expire(TimeSpan.FromMinutes(5)));

app.MapGet(
    "/api/scenarios/{id}",
    (string id, IScenarioStore store) =>
    {
        ScenarioDetail? scenario = store.GetById(id);

        return scenario is null
            ? Results.NotFound(new ProblemDetails
            {
                Title = "Scenario not found",
                Detail = $"No scenario with id '{id}' exists.",
                Status = StatusCodes.Status404NotFound
            })
            : Results.Ok(scenario);
    });

app.MapPost(
    "/api/workflows/analyze",
    async (
        AnalyzeWorkflowRequest? request,
        IWorkflowAnalysisService service,
        CancellationToken cancellationToken) =>
    {
        IResult? validationFailure =
            ValidateWorkflowRequest(
                request,
                maximumWorkflowCharacters);

        if (validationFailure is not null)
        {
            return validationFailure;
        }

        WorkflowAnalysisResult result =
            await service.AnalyzeAsync(
                new WorkflowDocument(
                    request!.FileName,
                    request.Content),
                cancellationToken);

        return !result.IsValid
            ? Results.Problem(
                title: "Workflow YAML could not be parsed",
                detail: string.Join(
                    " ",
                    result.ValidationErrors),
                statusCode:
                    StatusCodes.Status422UnprocessableEntity)
            : Results.Ok(result);
    })
    .Accepts<AnalyzeWorkflowRequest>("application/json")
    .Produces<WorkflowAnalysisResult>(
        StatusCodes.Status200OK)
    .ProducesProblem(StatusCodes.Status400BadRequest)
    .ProducesProblem(StatusCodes.Status413PayloadTooLarge)
    .ProducesProblem(StatusCodes.Status415UnsupportedMediaType)
    .ProducesProblem(
        StatusCodes.Status422UnprocessableEntity)
    .RequireRateLimiting("workflow-analysis");

app.MapPost(
    "/api/workflows/remediation",
    async (
        AnalyzeWorkflowRequest? request,
        IRemediationReportService service,
        CancellationToken cancellationToken) =>
    {
        IResult? validationFailure =
            ValidateWorkflowRequest(
                request,
                maximumWorkflowCharacters);

        if (validationFailure is not null)
        {
            return validationFailure;
        }

        RemediationReport report =
            await service.BuildAsync(
                new WorkflowDocument(
                    request!.FileName,
                    request.Content),
                cancellationToken);

        return !report.OriginalAnalysis.IsValid
            ? Results.Problem(
                title: "Workflow YAML could not be parsed",
                detail: string.Join(
                    " ",
                    report.OriginalAnalysis.ValidationErrors),
                statusCode:
                    StatusCodes.Status422UnprocessableEntity)
            : Results.Ok(report);
    })
    .RequireRateLimiting("workflow-analysis");

app.MapPost(
    "/api/workflows/remediation/export/{format}",
    async (
        string format,
        AnalyzeWorkflowRequest? request,
        IRemediationReportService service,
        CancellationToken cancellationToken) =>
    {
        IResult? validationFailure =
            ValidateWorkflowRequest(
                request,
                maximumWorkflowCharacters);

        if (validationFailure is not null)
        {
            return validationFailure;
        }

        RemediationReport report =
            await service.BuildAsync(
                new WorkflowDocument(
                    request!.FileName,
                    request.Content),
                cancellationToken);

        string safeName =
            Path.GetFileNameWithoutExtension(request.FileName);

        return format.ToLowerInvariant() switch
        {
            "markdown" or "md" =>
                Results.File(
                    System.Text.Encoding.UTF8.GetBytes(
                        RemediationExports.Markdown(report)),
                    "text/markdown",
                    $"{safeName}-remediation.md"),

            "html" =>
                Results.File(
                    System.Text.Encoding.UTF8.GetBytes(
                        RemediationExports.Html(report)),
                    "text/html",
                    $"{safeName}-remediation.html"),

            "sarif" =>
                Results.Json(
                    RemediationExports.Sarif(report),
                    contentType: "application/sarif+json"),

            "json" =>
                Results.File(
                    System.Text.Encoding.UTF8.GetBytes(
                        RemediationExports.Json(report)),
                    "application/json",
                    $"{safeName}-remediation.json"),

            "diff" or "patch" =>
                Results.File(
                    System.Text.Encoding.UTF8.GetBytes(
                        string.Join(
                            "\n",
                            report.UnifiedDiff)),
                    "text/x-diff",
                    $"{safeName}.patch"),

            _ =>
                Results.Problem(
                    statusCode:
                        StatusCodes.Status400BadRequest,
                    title: "Unsupported export format",
                    detail:
                        "Supported formats: markdown, html, " +
                        "sarif, json, diff.")
        };
    })
    .RequireRateLimiting("workflow-analysis");

app.MapPost(
    "/api/workflows/explain",
    async (
        ExplainWorkflowRequest? request,
        IWorkflowExplanationService service,
        CancellationToken cancellationToken) =>
    {
        IResult? validationFailure =
            ValidateWorkflowRequest(
                request is null
                    ? null
                    : new AnalyzeWorkflowRequest(
                        request.FileName,
                        request.Content),
                maximumWorkflowCharacters);

        if (validationFailure is not null)
        {
            return validationFailure;
        }

        WorkflowExplanationResult result =
            await service.ExplainAsync(
                new WorkflowDocument(
                    request!.FileName,
                    request.Content),
                request.UseAi,
                cancellationToken);

        return !result.Analysis.IsValid
            ? Results.Problem(
                title: "Workflow YAML could not be parsed",
                detail: string.Join(
                    " ",
                    result.Analysis.ValidationErrors),
                statusCode:
                    StatusCodes.Status422UnprocessableEntity)
            : Results.Ok(result);
    })
    .Accepts<ExplainWorkflowRequest>("application/json")
    .Produces<WorkflowExplanationResult>(
        StatusCodes.Status200OK)
    .ProducesProblem(StatusCodes.Status400BadRequest)
    .ProducesProblem(StatusCodes.Status413PayloadTooLarge)
    .ProducesProblem(StatusCodes.Status415UnsupportedMediaType)
    .ProducesProblem(
        StatusCodes.Status422UnprocessableEntity)
    .RequireRateLimiting("workflow-analysis");

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

static IResult? ValidateWorkflowRequest(
    AnalyzeWorkflowRequest? request,
    int maximumCharacters)
{
    if (request is null ||
        string.IsNullOrWhiteSpace(request.FileName) ||
        string.IsNullOrWhiteSpace(request.Content))
    {
        return Results.BadRequest(new ProblemDetails
        {
            Title = "Invalid workflow request",
            Detail = "Both fileName and content are required.",
            Status = StatusCodes.Status400BadRequest
        });
    }

    if (request.Content.Length > maximumCharacters)
    {
        return Results.Problem(
            title: "Workflow is too large",
            detail:
                $"Workflow content cannot exceed " +
                $"{maximumCharacters:N0} characters.",
            statusCode:
                StatusCodes.Status413PayloadTooLarge);
    }

    return null;
}

public partial class Program;
