using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DevSecOpsSentinel.Api.Operational;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace DevSecOpsSentinel.Api.Security;

public sealed class ApiKeyAuthenticationMiddleware(
    RequestDelegate next,
    IOptionsMonitor<ApiSecurityOptions> optionsMonitor,
    IWebHostEnvironment environment,
    ILogger<ApiKeyAuthenticationMiddleware> logger)
{
    public async Task InvokeAsync(
        HttpContext context,
        CallerAuthentication caller)
    {
        ApiSecurityOptions options = optionsMonitor.CurrentValue;

        // Recorded whether or not the path needs it: in Public mode an
        // anonymous request is served, but a key still changes what the model
        // is allowed to do for it.
        bool keyPresented = HasValidKey(context.Request, options);
        if (keyPresented)
        {
            caller.MarkAuthenticated();
        }

        if (!options.UsesApiKey ||
            keyPresented ||
            IsOpenRequest(context.Request.Path, options))
        {
            await next(context);
            return;
        }

        logger.LogWarning(
            "Rejected unauthorized request for {Method} {Path}.",
            LogSanitizer.ForLog(context.Request.Method),
            LogSanitizer.ForLog(context.Request.Path));

        await WriteUnauthorizedAsync(context);
    }

    /// <summary>
    /// Endpoints that borrow a credential or spend money. These need the key in
    /// every mode that uses one, including Public.
    /// </summary>
    private static bool IsPrivileged(PathString path) =>
        path.StartsWithSegments("/api/github");

    private bool IsOpenRequest(PathString path, ApiSecurityOptions options)
    {
        if (path == "/" ||
            path.StartsWithSegments("/api/health") ||
            path == "/api/security/status")
        {
            return true;
        }

        if ((environment.IsDevelopment() || environment.IsEnvironment("Testing")) &&
            (path.StartsWithSegments("/openapi") || path.StartsWithSegments("/scalar")))
        {
            return true;
        }

        // Everything the deterministic engine serves. It parses text and
        // applies rules to it - no outbound call, no credential, no state - so
        // an anonymous caller can reach nothing they should not and cost
        // nothing by trying.
        return options.IsPublicScanner && !IsPrivileged(path);
    }

    private static bool HasValidKey(
        HttpRequest request,
        ApiSecurityOptions options)
    {
        if (!options.UsesApiKey ||
            !request.Headers.TryGetValue(
                options.HeaderName,
                out var suppliedValues) ||
            suppliedValues.Count != 1)
        {
            return false;
        }

        return IsValidKey(suppliedValues[0], options.ApiKey);
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
