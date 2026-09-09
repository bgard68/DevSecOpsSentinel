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
                LogSanitizer.ForLog(httpContext.Request.Method),
                LogSanitizer.ForLog(httpContext.Request.Path));
        }
        else
        {
            logger.LogError(
                exception,
                "Unhandled request failure for {Method} {Path}",
                LogSanitizer.ForLog(httpContext.Request.Method),
                LogSanitizer.ForLog(httpContext.Request.Path));
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
            // The content type has to be passed to WriteAsJsonAsync rather than
            // assigned beforehand: the overload without it resets the header to
            // application/json, so this fallback served a problem document under
            // a media type RFC 7807 clients do not recognise.
            await httpContext.Response.WriteAsJsonAsync(
                problem,
                options: null,
                contentType: "application/problem+json",
                cancellationToken);
        }

        return true;
    }
}
