namespace DevSecOpsSentinel.Api.Operational;

public sealed class CorrelationIdMiddleware(RequestDelegate next, ILogger<CorrelationIdMiddleware> logger)
{
    public const string HeaderName = "X-Correlation-ID";

    public async Task InvokeAsync(HttpContext context)
    {
        string correlationId = context.Request.Headers.TryGetValue(HeaderName, out var value)
            && !string.IsNullOrWhiteSpace(value)
            ? value.ToString()
            : Guid.NewGuid().ToString("N");

        context.TraceIdentifier = correlationId;
        context.Response.Headers[HeaderName] = correlationId;
        using IDisposable? scope = logger.BeginScope(new Dictionary<string, object>
        {
            ["CorrelationId"] = correlationId
        });
        await next(context);
    }
}
