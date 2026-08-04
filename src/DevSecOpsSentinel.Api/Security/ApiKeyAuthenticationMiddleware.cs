using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;

namespace DevSecOpsSentinel.Api.Security;

public sealed class ApiKeyAuthenticationMiddleware(
    RequestDelegate next,
    ApiSecurityOptions options,
    IWebHostEnvironment environment,
    ILogger<ApiKeyAuthenticationMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        if (!options.IsRequired ||
            IsPublicRequest(context.Request.Path))
        {
            await next(context);
            return;
        }

        if (!context.Request.Headers.TryGetValue(
                options.HeaderName,
                out var suppliedValues) ||
            suppliedValues.Count != 1 ||
            !IsValidKey(suppliedValues[0]))
        {
            logger.LogWarning(
                "Rejected unauthorized request for {Method} {Path}.",
                context.Request.Method,
                context.Request.Path);

            await WriteUnauthorizedAsync(context);
            return;
        }

        await next(context);
    }

    private bool IsPublicRequest(PathString path)
    {
        if (path == "/" ||
            path.StartsWithSegments("/api/health"))
        {
            return true;
        }

        return (environment.IsDevelopment() ||
                environment.IsEnvironment("Testing")) &&
               (path.StartsWithSegments("/openapi") ||
                path.StartsWithSegments("/scalar"));
    }

    private bool IsValidKey(string? suppliedKey)
    {
        if (string.IsNullOrEmpty(suppliedKey))
        {
            return false;
        }

        byte[] expectedHash = SHA256.HashData(
            Encoding.UTF8.GetBytes(options.ApiKey));

        byte[] suppliedHash = SHA256.HashData(
            Encoding.UTF8.GetBytes(suppliedKey));

        return CryptographicOperations.FixedTimeEquals(
            expectedHash,
            suppliedHash);
    }

    private static async Task WriteUnauthorizedAsync(
        HttpContext context)
    {
        context.Response.StatusCode =
            StatusCodes.Status401Unauthorized;
        context.Response.ContentType =
            "application/problem+json";

        context.Response.Headers.WWWAuthenticate =
            "ApiKey";

        ProblemDetails problem = new()
        {
            Status = StatusCodes.Status401Unauthorized,
            Title = "Authentication required",
            Detail =
                "A valid API key must be supplied with this request."
        };

        await context.Response.WriteAsJsonAsync(
            problem,
            cancellationToken:
                context.RequestAborted);
    }
}
