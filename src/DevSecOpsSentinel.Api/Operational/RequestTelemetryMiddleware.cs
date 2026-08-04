using System.Diagnostics;

namespace DevSecOpsSentinel.Api.Operational;

public sealed class RequestTelemetryMiddleware(RequestDelegate next, ILogger<RequestTelemetryMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        long started = Stopwatch.GetTimestamp();
        try { await next(context); }
        finally
        {
            double elapsedMs = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
            logger.LogInformation(
                "HTTP {Method} {Path} returned {StatusCode} in {ElapsedMilliseconds:F1} ms",
                context.Request.Method,
                context.Request.Path,
                context.Response.StatusCode,
                elapsedMs);
        }
    }
}
