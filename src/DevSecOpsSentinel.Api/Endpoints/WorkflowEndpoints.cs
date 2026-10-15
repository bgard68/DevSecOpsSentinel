using DevSecOpsSentinel.Api.Security;
using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Api.Endpoints;

/// <summary>
/// Analysis, remediation preview and AI explanation for a workflow supplied in the
/// request. ADR-006 keeps remediation preview-only — nothing here writes to a repository.
///
/// Extracted from Program.cs, which had grown to 944 lines holding the composition root,
/// the middleware pipeline and every handler body at once.
///
/// The four endpoints share a route group, so the rate-limit policy and the request
/// validation are stated once. Each handler previously carried its own copy of both, and a
/// handler's first eight lines were the same eight lines as its neighbour's — which left
/// the character limit depending on whoever wrote the next endpoint remembering it.
/// </summary>
public static class WorkflowEndpoints
{
    public static WebApplication MapWorkflowEndpoints(
        this WebApplication app,
        int maximumWorkflowCharacters)
    {
        RouteGroupBuilder workflows = app
            .MapGroup("/api/workflows")
            .RequireRateLimiting("workflow-analysis")
            .AddEndpointFilter(
                new WorkflowRequestValidationFilter(maximumWorkflowCharacters));

        workflows.MapPost(
            "/analyze",
            async (
                AnalyzeWorkflowRequest? request,
                IWorkflowAnalysisService service,
                CancellationToken cancellationToken) =>
            {
                // The group's filter has already rejected a missing or blank request. This
                // pattern is how the compiler is told so, rather than a null-forgiving
                // operator asserting what another file established.
                if (request is null)
                {
                    return WorkflowRequestValidation.MissingOrInvalidRequest();
                }

                WorkflowAnalysisResult result = await service.AnalyzeAsync(
                    new WorkflowDocument(request.FileName, request.Content),
                    cancellationToken);

                return result.IsValid
                    ? Results.Ok(result)
                    : WorkflowRequestValidation.InvalidWorkflowYaml(result.ValidationErrors);
            })
            .Accepts<AnalyzeWorkflowRequest>("application/json")
            .Produces<WorkflowAnalysisResult>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status413PayloadTooLarge)
            .ProducesProblem(StatusCodes.Status415UnsupportedMediaType)
            .ProducesProblem(StatusCodes.Status422UnprocessableEntity);

        workflows.MapPost(
            "/remediation",
            async (
                AnalyzeWorkflowRequest? request,
                IRemediationReportService service,
                CancellationToken cancellationToken) =>
            {
                // The group's filter has already rejected a missing or blank request. This
                // pattern is how the compiler is told so, rather than a null-forgiving
                // operator asserting what another file established.
                if (request is null)
                {
                    return WorkflowRequestValidation.MissingOrInvalidRequest();
                }

                RemediationReport report = await service.BuildAsync(
                    new WorkflowDocument(request.FileName, request.Content),
                    cancellationToken);

                return report.OriginalAnalysis.IsValid
                    ? Results.Ok(report)
                    : WorkflowRequestValidation.InvalidWorkflowYaml(
                        report.OriginalAnalysis.ValidationErrors);
            })
            .Accepts<AnalyzeWorkflowRequest>("application/json")
            .Produces<RemediationReport>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status413PayloadTooLarge)
            .ProducesProblem(StatusCodes.Status422UnprocessableEntity);

        workflows.MapPost(
            "/remediation/export/{format}",
            async (
                string format,
                AnalyzeWorkflowRequest? request,
                IRemediationReportService service,
                CancellationToken cancellationToken) =>
            {
                // The group's filter has already rejected a missing or blank request. This
                // pattern is how the compiler is told so, rather than a null-forgiving
                // operator asserting what another file established.
                if (request is null)
                {
                    return WorkflowRequestValidation.MissingOrInvalidRequest();
                }

                IRemediationExporter? exporter = RemediationExporters.For(format);

                if (exporter is null)
                {
                    return Results.Problem(
                        statusCode: StatusCodes.Status400BadRequest,
                        title: "Unsupported export format",
                        detail:
                            $"Supported formats: {RemediationExporters.SupportedFormats}.");
                }

                RemediationReport report = await service.BuildAsync(
                    new WorkflowDocument(request.FileName, request.Content),
                    cancellationToken);

                RemediationExportResponse export = exporter.Render(
                    report,
                    Path.GetFileNameWithoutExtension(request.FileName));

                // Inline for a format a tool reads from the response body, a download for
                // one a person saves. The exporter decides which; this does not need to
                // know the list.
                return export.DownloadName is null
                    ? Results.Bytes(export.Content, export.ContentType)
                    : Results.File(export.Content, export.ContentType, export.DownloadName);
            })
            .Accepts<AnalyzeWorkflowRequest>("application/json")
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status413PayloadTooLarge);

        workflows.MapPost(
            "/explain",
            async (
                ExplainWorkflowRequest? request,
                IWorkflowExplanationService service,
                CallerAuthentication caller,
                CancellationToken cancellationToken) =>
            {
                // The group's filter has already rejected a missing or blank request. This
                // pattern is how the compiler is told so, rather than a null-forgiving
                // operator asserting what another file established.
                if (request is null)
                {
                    return WorkflowRequestValidation.MissingOrInvalidRequest();
                }

                WorkflowExplanationResult result = await service.ExplainAsync(
                    new WorkflowDocument(request.FileName, request.Content),
                    request.UseAi,
                    caller.AiAccess == AiAccess.Full
                        ? AiCallerAccess.Configured
                        : AiCallerAccess.MockOnly,
                    cancellationToken);

                return result.Analysis.IsValid
                    ? Results.Ok(result)
                    : WorkflowRequestValidation.InvalidWorkflowYaml(
                        result.Analysis.ValidationErrors);
            })
            .Accepts<ExplainWorkflowRequest>("application/json")
            .Produces<WorkflowExplanationResult>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status413PayloadTooLarge)
            .ProducesProblem(StatusCodes.Status415UnsupportedMediaType)
            .ProducesProblem(StatusCodes.Status422UnprocessableEntity);

        return app;
    }
}
