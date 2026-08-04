using System.Text.Json;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace DevSecOpsSentinel.Api.Operational;

public sealed class ApiExceptionHandler(
    ILogger<ApiExceptionHandler> logger,
    IProblemDetailsService problemDetailsService) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        bool invalidRequest = exception is BadHttpRequestException or JsonException;
        int statusCode = invalidRequest
            ? StatusCodes.Status400BadRequest
            : StatusCodes.Status500InternalServerError;

        if (invalidRequest)
        {
            logger.LogWarning(
                "Rejected malformed request for {Method} {Path}",
                httpContext.Request.Method,
                httpContext.Request.Path);
        }
        else
        {
            logger.LogError(
                exception,
                "Unhandled request failure for {Method} {Path}",
                httpContext.Request.Method,
                httpContext.Request.Path);
        }

        httpContext.Response.StatusCode = statusCode;
        httpContext.Response.ContentType = "application/problem+json";

        var problem = new ProblemDetails
        {
            Status = statusCode,
            Title = invalidRequest ? "Invalid request body" : "Unexpected server error",
            Detail = invalidRequest ? "The request body contains malformed JSON." : null,
            Instance = httpContext.Request.Path
        };

        bool written = await problemDetailsService.TryWriteAsync(new ProblemDetailsContext
        {
            HttpContext = httpContext,
            ProblemDetails = problem
        });

        if (!written && !httpContext.Response.HasStarted)
        {
            httpContext.Response.ContentType = "application/problem+json";

            await httpContext.Response.WriteAsJsonAsync(
                problem,
                cancellationToken);
        }

        return true;
    }
}
