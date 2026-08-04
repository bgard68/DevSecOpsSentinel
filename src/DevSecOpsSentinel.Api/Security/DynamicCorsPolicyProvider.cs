using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.Extensions.Options;

namespace DevSecOpsSentinel.Api.Security;

public sealed class DynamicCorsPolicyProvider(
    IOptionsMonitor<ApiSecurityOptions> optionsMonitor)
    : ICorsPolicyProvider
{
    public Task<CorsPolicy?> GetPolicyAsync(
        HttpContext context,
        string? policyName)
    {
        if (!string.Equals(
            policyName,
            "frontend",
            StringComparison.Ordinal))
        {
            return Task.FromResult<CorsPolicy?>(null);
        }

        ApiSecurityOptions options = optionsMonitor.CurrentValue;

        CorsPolicyBuilder builder = new();

        if (options.AllowedOrigins.Length > 0)
        {
            builder
                .WithOrigins(options.AllowedOrigins)
                .WithMethods("GET", "POST")
                .WithHeaders(
                    "Content-Type",
                    options.HeaderName,
                    "X-Correlation-ID");
        }

        return Task.FromResult<CorsPolicy?>(builder.Build());
    }
}
