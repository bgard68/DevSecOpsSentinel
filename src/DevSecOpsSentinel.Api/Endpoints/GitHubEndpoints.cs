using System.Text.Json;
using DevSecOpsSentinel.Api.Security;
using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;
using DevSecOpsSentinel.Infrastructure.Ai;
using DevSecOpsSentinel.Infrastructure.GitHub;
using Microsoft.AspNetCore.Mvc;

namespace DevSecOpsSentinel.Api.Endpoints;

/// <summary>
/// Repository, workflow and analysis endpoints backed by the read-only GitHub App.
/// ADR-004 keeps the installation read-only, so nothing here writes.
///
/// Extracted from Program.cs, which had grown to 944 lines holding the composition root,
/// the middleware pipeline and every handler body at once.
/// </summary>
public static class GitHubEndpoints
{
    // Options come from DI per request rather than a parameter captured at map time. The
    // captured copy was read from configuration before Build(), which made it a second
    // source of truth — one a test host provably could not influence, and one that would
    // disagree with the container's copy if registration ever changed. One source now.
    public static WebApplication MapGitHubEndpoints(this WebApplication app)
    {
    app.MapGet(
        "/api/github/status",
        async (
            GitHubOptions gitHubOptions,
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
            GitHubOptions gitHubOptions,
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
            GitHubOptions gitHubOptions,
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
            GitHubOptions gitHubOptions,
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
            GitHubOptions gitHubOptions,
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
                // Reaching this endpoint at all requires the key - /api/github is
                // privileged in every mode - so the caller is identified and the
                // configured provider applies.
                WorkflowExplanationResult explained =
                    await explanationService.ExplainAsync(
                        document,
                        true,
                        AiCallerAccess.Configured,
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

        return app;
    }
}
