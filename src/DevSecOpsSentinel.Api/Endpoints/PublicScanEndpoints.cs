using DevSecOpsSentinel.Application;
using Microsoft.AspNetCore.Mvc;

namespace DevSecOpsSentinel.Api.Endpoints;

/// <summary>
/// Scan any public repository's workflows by name, anonymously.
///
/// This deliberately amends the middleware's "no outbound call" justification for
/// anonymous access: this endpoint does call out, and the amended boundary is
/// stated rather than implied — api.github.com and raw.githubusercontent.com
/// only, no credential attached, read-only by construction, results cached so a
/// visitor cannot spend the unauthenticated GitHub quota one refresh at a time.
/// Private repositories cannot appear here: an anonymous request cannot see them,
/// which is why this path needs no allowlist while /api/github does.
/// </summary>
public static class PublicScanEndpoints
{
    public static WebApplication MapPublicScanEndpoints(this WebApplication app)
    {
        app.MapGet(
            "/api/public-scan/{owner}/{repository}",
            async (
                string owner,
                string repository,
                IPublicRepositoryScanner scanner,
                CancellationToken cancellationToken) =>
            {
                PublicScanResult result =
                    await scanner.ScanAsync(owner, repository, cancellationToken);

                return result.Status switch
                {
                    PublicScanStatus.Completed or PublicScanStatus.NoWorkflows =>
                        Results.Ok(result),

                    PublicScanStatus.InvalidName => Results.BadRequest(new ProblemDetails
                    {
                        Title = "Invalid repository name",
                        Detail = result.Detail,
                        Status = StatusCodes.Status400BadRequest
                    }),

                    PublicScanStatus.RepositoryNotFound => Results.NotFound(new ProblemDetails
                    {
                        Title = "Repository not found",
                        Detail = result.Detail,
                        Status = StatusCodes.Status404NotFound
                    }),

                    PublicScanStatus.QuotaExhausted => Results.Json(
                        new ProblemDetails
                        {
                            Title = "GitHub quota exhausted",
                            Detail = result.Detail,
                            Status = StatusCodes.Status503ServiceUnavailable
                        },
                        statusCode: StatusCodes.Status503ServiceUnavailable),

                    _ => Results.Json(
                        new ProblemDetails
                        {
                            Title = "GitHub unavailable",
                            Detail = result.Detail,
                            Status = StatusCodes.Status502BadGateway
                        },
                        statusCode: StatusCodes.Status502BadGateway)
                };
            })
            .RequireRateLimiting("workflow-analysis");

        return app;
    }
}
