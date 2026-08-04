namespace DevSecOpsSentinel.Api.Operational;

public sealed class SecurityHeadersMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context)
    {
        context.Response.OnStarting(() =>
        {
            context.Response.Headers.TryAdd(
                "X-Content-Type-Options",
                "nosniff");
            context.Response.Headers.TryAdd(
                "X-Frame-Options",
                "DENY");
            context.Response.Headers.TryAdd(
                "Referrer-Policy",
                "no-referrer");
            context.Response.Headers.TryAdd(
                "Permissions-Policy",
                "camera=(), microphone=(), geolocation=()");
            context.Response.Headers.TryAdd(
                "Content-Security-Policy",
                BuildContentSecurityPolicy(context.Request.Path));
            return Task.CompletedTask;
        });

        await next(context);
    }

    private static string BuildContentSecurityPolicy(PathString path)
    {
        if (path.StartsWithSegments("/scalar"))
        {
            return
                "default-src 'self'; " +
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
                "img-src 'self' data:; connect-src 'self'; " +
                "font-src 'self' data:; frame-ancestors 'none'; " +
                "base-uri 'self'; form-action 'self'";
        }

        return
            "default-src 'none'; frame-ancestors 'none'; " +
            "base-uri 'none'; form-action 'none'";
    }
}
