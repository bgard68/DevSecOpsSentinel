using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace DevSecOpsSentinel.Api.Security;

public sealed class ApiKeyAuthenticationMiddleware(
    RequestDelegate next,
    IOptionsMonitor<ApiSecurityOptions> optionsMonitor,
    IWebHostEnvironment environment,
    ILogger<ApiKeyAuthenticationMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        ApiSecurityOptions options = optionsMonitor.CurrentValue;

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
            !IsValidKey(
                suppliedValues[0],
                options.ApiKey))
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
            path.StartsWithSegments("/api/health") ||
            path == "/api/security/status")
        {
            return true;
        }

        return (environment.IsDevelopment() ||
                environment.IsEnvironment("Testing")) &&
               (path.StartsWithSegments("/openapi") ||
                path.StartsWithSegments("/scalar"));
    }

    private static bool IsValidKey(
        string? suppliedKey,
        string configuredKey)
    {
        if (string.IsNullOrEmpty(suppliedKey) ||
            string.IsNullOrEmpty(configuredKey))
        {
            return false;
        }

        byte[] expectedHash = SHA256.HashData(
            Encoding.UTF8.GetBytes(configuredKey));

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

        await JsonSerializer.SerializeAsync(
            context.Response.Body,
            problem,
            cancellationToken:
                context.RequestAborted);
    }
}
