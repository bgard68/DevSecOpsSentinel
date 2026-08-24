using System.Text.Json;
using DevSecOpsSentinel.Api.Security;
using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;
using DevSecOpsSentinel.Infrastructure.Ai;
using DevSecOpsSentinel.Infrastructure.GitHub;
using Microsoft.AspNetCore.Mvc;

namespace DevSecOpsSentinel.Api.Endpoints;

/// <summary>
/// Analysis, remediation preview and AI explanation for a workflow supplied in the
/// request. ADR-006 keeps remediation preview-only — nothing here writes to a repository.
///
/// Extracted from Program.cs, which had grown to 944 lines holding the composition root,
/// the middleware pipeline and every handler body at once.
/// </summary>
public static class WorkflowEndpoints
{
    public static WebApplication MapWorkflowEndpoints(this WebApplication app, int maximumWorkflowCharacters)
    {
    app.MapPost(
        "/api/workflows/analyze",
        async (
            AnalyzeWorkflowRequest? request,
            IWorkflowAnalysisService service,
            CancellationToken cancellationToken) =>
        {
            if (request is null)
            {
                return MissingOrInvalidRequest();
            }
            
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
                        request.FileName,
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
            if (request is null)
            {
                return MissingOrInvalidRequest();
            }
            
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
                        request.FileName,
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
            if (request is null)
            {
                return MissingOrInvalidRequest();
            }
            
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
                        request.FileName,
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
            CallerAuthentication caller,
            CancellationToken cancellationToken) =>
        {
            if (request is null)
            {
                return MissingOrInvalidRequest();
            }

            IResult? validationFailure =
                ValidateWorkflowRequest(
                    new AnalyzeWorkflowRequest(
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
                        request.FileName,
                        request.Content),
                    request.UseAi,
                    caller.AiAccess == AiAccess.Full
                        ? AiCallerAccess.Configured
                        : AiCallerAccess.MockOnly,
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

        return app;
    }

    /// <summary>
    /// A missing body and an invalid one produce the same problem response, but they are
    /// checked in different places: the null test lives at each call site so the compiler —
    /// and the analyzer — can see the proof, instead of a null-forgiving operator asserting
    /// what a helper established somewhere else.
    /// </summary>
    private static IResult MissingOrInvalidRequest() =>
        Results.BadRequest(new ProblemDetails
        {
            Title = "Invalid workflow request",
            Detail = "Both fileName and content are required.",
            Status = StatusCodes.Status400BadRequest
        });

    private static IResult? ValidateWorkflowRequest(
        AnalyzeWorkflowRequest request,
        int maximumCharacters)
    {
        if (string.IsNullOrWhiteSpace(request.FileName) ||
            string.IsNullOrWhiteSpace(request.Content))
        {
            return MissingOrInvalidRequest();
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
}
