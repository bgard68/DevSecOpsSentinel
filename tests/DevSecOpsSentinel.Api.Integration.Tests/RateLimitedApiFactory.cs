using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using DevSecOpsSentinel.Application;

namespace DevSecOpsSentinel.Api.Integration.Tests;

/// <summary>
/// Runs the API with a deliberately tiny request budget so the rejection path is
/// reachable inside a test. The production default of thirty a minute cannot be
/// exhausted without either sleeping or firing thirty-one requests, so the limit
/// itself is configured down rather than the test working around it.
///
/// This factory is isolated from <see cref="ApiFactory"/> because the window is
/// shared across every request the host serves; a low limit would otherwise make
/// unrelated tests fail once they exhausted it.
/// </summary>
public sealed class RateLimitedApiFactory : WebApplicationFactory<Program>
{
    public const int PermitLimit = 2;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.ConfigureAppConfiguration((_, configuration) =>
        {
            configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["OpenAI:Mode"] = "Mock",
                ["OpenAI:ApiKey"] = string.Empty,
                ["GitHub:Enabled"] = "false",
                ["GitHub:ResolveActionReferences"] = "false",
                ["GitHub:AppId"] = "0",
                ["GitHub:InstallationId"] = "0",
                ["GitHub:PrivateKeyPath"] = string.Empty,
                ["GitHub:AllowedRepositories:0"] = null,
                ["Security:Mode"] = "Disabled",
                ["Security:ApiKey"] = string.Empty,
                ["Operational:WorkflowRequestLimitPerMinute"] =
                    PermitLimit.ToString()
            });
        });

        builder.ConfigureServices(services =>
        {
            services.RemoveAll<IWorkflowActionReferenceResolver>();
            services.AddSingleton<
                IWorkflowActionReferenceResolver,
                StubActionReferenceResolver>();
        });
    }

    private sealed class StubActionReferenceResolver :
        IWorkflowActionReferenceResolver
    {
        public Task<ActionReferenceResolutionResult> ResolveAsync(
            string actionReference,
            CancellationToken cancellationToken) =>
            Task.FromResult(
                new ActionReferenceResolutionResult(
                    ActionReferenceResolutionStatus.Failed,
                    null,
                    "Integration tests do not perform live GitHub lookups."));
    }
}
