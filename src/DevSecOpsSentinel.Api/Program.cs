using System.Text.Json;
using DevSecOpsSentinel.Api;
using DevSecOpsSentinel.Api.Operational;
using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;
using DevSecOpsSentinel.Infrastructure;
using DevSecOpsSentinel.Infrastructure.Ai;
using DevSecOpsSentinel.Infrastructure.GitHub;
using DevSecOpsSentinel.Infrastructure.Rules;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Mvc;
using Scalar.AspNetCore;

const int maximumWorkflowCharacters = 100_000;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<ApiExceptionHandler>();
builder.Services.AddOpenApi();
builder.Services.AddOutputCache();
builder.Services.AddMemoryCache();
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddFixedWindowLimiter("workflow-analysis", limiter =>
    {
        limiter.PermitLimit = 30;
        limiter.Window = TimeSpan.FromMinutes(1);
        limiter.QueueLimit = 0;
        limiter.AutoReplenishment = true;
    });
});
builder.Services.Configure<FormOptions>(options =>
{
    options.ValueLengthLimit = maximumWorkflowCharacters;
});

string scenarioDirectory = Path.Combine(AppContext.BaseDirectory, "Scenarios");
builder.Services.AddSingleton<IWorkflowParser, WorkflowParser>();
builder.Services.AddSingleton<IWorkflowSecurityRule, UnpinnedActionRule>();
builder.Services.AddSingleton<IWorkflowSecurityRule, ExcessivePermissionsRule>();
builder.Services.AddSingleton<IWorkflowSecurityRule, MissingTimeoutRule>();
builder.Services.AddSingleton<IWorkflowSecurityRule, UnsafePullRequestTargetRule>();
builder.Services.AddSingleton<IWorkflowPatchGenerator, WorkflowPatchGenerator>();
builder.Services.AddSingleton<IWorkflowAnalysisService, WorkflowAnalysisService>();
builder.Services.AddSingleton<IRemediationReportService, RemediationReportService>();
builder.Services.AddSingleton<IScenarioStore>(_ => new FileScenarioStore(scenarioDirectory));
builder.Services.AddSingleton<ISensitiveDataSanitizer, SensitiveDataSanitizer>();

OpenAiOptions openAiOptions = builder.Configuration
    .GetSection(OpenAiOptions.SectionName)
    .Get<OpenAiOptions>() ?? new OpenAiOptions();
builder.Services.AddSingleton(openAiOptions);
builder.Services.AddSingleton<IWorkflowAiProvider>(_ =>
    openAiOptions.Mode.ToUpperInvariant() switch
    {
        "LIVE" => new OpenAiWorkflowAiProvider(openAiOptions),
        "DISABLED" => new DisabledWorkflowAiProvider(),
        _ => new MockWorkflowAiProvider()
    });
builder.Services.AddSingleton<IWorkflowExplanationService, WorkflowExplanationService>();

GitHubOptions gitHubOptions = builder.Configuration
    .GetSection(GitHubOptions.SectionName)
    .Get<GitHubOptions>() ?? new GitHubOptions();
builder.Services.AddSingleton(gitHubOptions);
builder.Services.AddSingleton(new HttpClient());
builder.Services.AddSingleton<GitHubAppJwtFactory>();
builder.Services.AddSingleton<IGitHubInstallationTokenProvider, GitHubInstallationTokenProvider>();
builder.Services.AddSingleton<IGitHubRepositoryReader, GitHubRepositoryReader>();

WebApplication app = builder.Build();

if (app.Environment.IsDevelopment() || app.Environment.IsEnvironment("Testing"))
{
    app.MapOpenApi();
    app.MapScalarApiReference(options =>
    {
        options.WithTitle("DevSecOps Sentinel API");
    });
}

app.UseExceptionHandler();
app.UseMiddleware<CorrelationIdMiddleware>();
app.UseMiddleware<RequestTelemetryMiddleware>();
app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseRateLimiter();
app.UseOutputCache();

app.UseHttpsRedirection();

app.MapGet("/", () => Results.Ok(new
{
    status = "Running",
    application = "DevSecOps Sentinel",
    phase = "F",
    message = "Open /scalar for API documentation or http://localhost:5173 for the React application."
}));

app.MapGet("/api/health", () => Results.Ok(new
{
    status = "Healthy",
    application = "DevSecOps Sentinel",
    version = "1.0.0",
    phase = "F"
}));

app.MapGet("/api/health/live", () => Results.Ok(new
{
    status = "Healthy",
    check = "Liveness",
    timestampUtc = DateTimeOffset.UtcNow
})).CacheOutput(policy => policy.Expire(TimeSpan.FromSeconds(10)));

app.MapGet("/api/health/ready", () =>
{
    bool privateKeyAvailable = !gitHubOptions.Enabled
        || (!string.IsNullOrWhiteSpace(gitHubOptions.PrivateKeyPath)
            && File.Exists(gitHubOptions.PrivateKeyPath));
    bool ready = !gitHubOptions.Enabled || (gitHubOptions.IsConfigured && privateKeyAvailable);
    return ready
        ? Results.Ok(new { status = "Ready", gitHubMode = gitHubOptions.Enabled ? "ReadOnly" : "Disabled", timestampUtc = DateTimeOffset.UtcNow })
        : Results.Problem(statusCode: StatusCodes.Status503ServiceUnavailable, title: "Application is not ready", detail: "GitHub configuration or private-key access is incomplete.");
});

app.MapGet("/api/ai/status", () =>
{
    bool configured = !string.IsNullOrWhiteSpace(openAiOptions.ApiKey);
    return Results.Ok(new
    {
        enabled = !string.Equals(openAiOptions.Mode, "Disabled", StringComparison.OrdinalIgnoreCase),
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

app.MapGet("/api/github/status", async (
    IGitHubRepositoryReader reader,
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
            "Connected using a short-lived GitHub App installation token."));
    }
    catch (Exception)
    {
        return Results.Ok(new GitHubConnectionStatus(
            true,
            true,
            false,
            "ReadOnly",
            gitHubOptions.AllowedRepositories.Length,
            "GitHub could not be reached or authentication failed."));
    }
});

app.MapGet("/api/github/repositories", async (
    IGitHubRepositoryReader reader,
    CancellationToken cancellationToken) =>
{
    if (!gitHubOptions.IsConfigured)
    {
        return Results.Problem(
            title: "GitHub integration is not configured",
            statusCode: StatusCodes.Status503ServiceUnavailable);
    }

    return Results.Ok(await reader.GetRepositoriesAsync(cancellationToken));
});

app.MapGet("/api/github/repositories/{owner}/{repository}/workflows", async (
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
            detail: "The requested repository is not included in the configured allowlist.");
    }

    return Results.Ok(await reader.GetWorkflowsAsync(owner, repository, cancellationToken));
});

app.MapGet("/api/github/repositories/{owner}/{repository}/workflows/content", async (
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
            detail: "The requested repository is not included in the configured allowlist.");
    }

    GitHubWorkflowFile? workflow = await reader.GetWorkflowAsync(
        owner,
        repository,
        path,
        reference,
        cancellationToken);
    return workflow is null ? Results.NotFound() : Results.Ok(workflow);
});

app.MapPost("/api/github/repositories/{owner}/{repository}/analyze", async (
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
            detail: "The requested repository is not included in the configured allowlist.");
    }

    if (request is null || string.IsNullOrWhiteSpace(request.Path))
    {
        return Results.BadRequest(new ProblemDetails
        {
            Title = "Invalid GitHub workflow request",
            Detail = "A workflow path is required.",
            Status = StatusCodes.Status400BadRequest
        });
    }

    GitHubWorkflowFile? workflow = await reader.GetWorkflowAsync(
        owner,
        repository,
        request.Path,
        request.Reference,
        cancellationToken);
    if (workflow is null)
    {
        return Results.NotFound();
    }

    WorkflowDocument document = new(Path.GetFileName(workflow.Path), workflow.Content);
    if (request.UseAi)
    {
        WorkflowExplanationResult explained = await explanationService.ExplainAsync(
            document,
            true,
            cancellationToken);
        return Results.Ok(new { source = workflow, result = explained });
    }

    WorkflowAnalysisResult analyzed = analysisService.Analyze(document);
    return Results.Ok(new { source = workflow, result = analyzed });
});

app.MapGet("/api/rules", (IEnumerable<IWorkflowSecurityRule> rules) =>
    Results.Ok(rules.Select(rule => new
    {
        rule.RuleId,
        rule.Title,
        severity = rule.Severity.ToString()
    }).OrderBy(rule => rule.RuleId))).CacheOutput(policy => policy.Expire(TimeSpan.FromMinutes(5)));

app.MapGet("/api/scenarios", (IScenarioStore store) => Results.Ok(store.GetAll()))
    .CacheOutput(policy => policy.Expire(TimeSpan.FromMinutes(5)));

app.MapGet("/api/scenarios/{id}", (string id, IScenarioStore store) =>
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

app.MapPost("/api/workflows/analyze", (
    AnalyzeWorkflowRequest? request,
    IWorkflowAnalysisService service) =>
{
    IResult? validationFailure = ValidateWorkflowRequest(request, maximumWorkflowCharacters);
    if (validationFailure is not null)
    {
        return validationFailure;
    }

    WorkflowAnalysisResult result = service.Analyze(
        new WorkflowDocument(request!.FileName, request.Content));

    return !result.IsValid
        ? Results.Problem(
            title: "Workflow YAML could not be parsed",
            detail: string.Join(" ", result.ValidationErrors),
            statusCode: StatusCodes.Status422UnprocessableEntity)
        : Results.Ok(result);
})
.Accepts<AnalyzeWorkflowRequest>("application/json")
.Produces<WorkflowAnalysisResult>(StatusCodes.Status200OK)
.ProducesProblem(StatusCodes.Status400BadRequest)
.ProducesProblem(StatusCodes.Status413PayloadTooLarge)
.ProducesProblem(StatusCodes.Status415UnsupportedMediaType)
.ProducesProblem(StatusCodes.Status422UnprocessableEntity)
.RequireRateLimiting("workflow-analysis");


app.MapPost("/api/workflows/remediation", (
    AnalyzeWorkflowRequest? request,
    IRemediationReportService service) =>
{
    IResult? validationFailure = ValidateWorkflowRequest(request, maximumWorkflowCharacters);
    if (validationFailure is not null) return validationFailure;

    RemediationReport report = service.Build(new WorkflowDocument(request!.FileName, request.Content));
    return !report.OriginalAnalysis.IsValid
        ? Results.Problem(
            title: "Workflow YAML could not be parsed",
            detail: string.Join(" ", report.OriginalAnalysis.ValidationErrors),
            statusCode: StatusCodes.Status422UnprocessableEntity)
        : Results.Ok(report);
})
.RequireRateLimiting("workflow-analysis");

app.MapPost("/api/workflows/remediation/export/{format}", (
    string format,
    AnalyzeWorkflowRequest? request,
    IRemediationReportService service) =>
{
    IResult? validationFailure = ValidateWorkflowRequest(request, maximumWorkflowCharacters);
    if (validationFailure is not null) return validationFailure;
    RemediationReport report = service.Build(new WorkflowDocument(request!.FileName, request.Content));
    string safeName = Path.GetFileNameWithoutExtension(request.FileName);
    return format.ToLowerInvariant() switch
    {
        "markdown" or "md" => Results.File(System.Text.Encoding.UTF8.GetBytes(RemediationExports.Markdown(report)), "text/markdown", $"{safeName}-remediation.md"),
        "html" => Results.File(System.Text.Encoding.UTF8.GetBytes(RemediationExports.Html(report)), "text/html", $"{safeName}-remediation.html"),
        "sarif" => Results.Json(RemediationExports.Sarif(report), contentType: "application/sarif+json"),
        "json" => Results.File(System.Text.Encoding.UTF8.GetBytes(RemediationExports.Json(report)), "application/json", $"{safeName}-remediation.json"),
        "diff" or "patch" => Results.File(System.Text.Encoding.UTF8.GetBytes(string.Join("\n", report.UnifiedDiff)), "text/x-diff", $"{safeName}.patch"),
        _ => Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: "Unsupported export format", detail: "Supported formats: markdown, html, sarif, json, diff.")
    };
})
.RequireRateLimiting("workflow-analysis");

app.MapPost("/api/workflows/explain", async (
    ExplainWorkflowRequest? request,
    IWorkflowExplanationService service,
    CancellationToken cancellationToken) =>
{
    IResult? validationFailure = ValidateWorkflowRequest(
        request is null ? null : new AnalyzeWorkflowRequest(request.FileName, request.Content),
        maximumWorkflowCharacters);
    if (validationFailure is not null)
    {
        return validationFailure;
    }

    WorkflowExplanationResult result = await service.ExplainAsync(
        new WorkflowDocument(request!.FileName, request.Content),
        request.UseAi,
        cancellationToken);

    return !result.Analysis.IsValid
        ? Results.Problem(
            title: "Workflow YAML could not be parsed",
            detail: string.Join(" ", result.Analysis.ValidationErrors),
            statusCode: StatusCodes.Status422UnprocessableEntity)
        : Results.Ok(result);
})
.Accepts<ExplainWorkflowRequest>("application/json")
.Produces<WorkflowExplanationResult>(StatusCodes.Status200OK)
.ProducesProblem(StatusCodes.Status400BadRequest)
.ProducesProblem(StatusCodes.Status413PayloadTooLarge)
.ProducesProblem(StatusCodes.Status415UnsupportedMediaType)
.ProducesProblem(StatusCodes.Status422UnprocessableEntity)
.RequireRateLimiting("workflow-analysis");

app.Run();

static IResult? ValidateWorkflowRequest(AnalyzeWorkflowRequest? request, int maximumCharacters)
{
    if (request is null || string.IsNullOrWhiteSpace(request.FileName) ||
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
            detail: $"Workflow content cannot exceed {maximumCharacters:N0} characters.",
            statusCode: StatusCodes.Status413PayloadTooLarge);
    }

    return null;
}

public partial class Program;
