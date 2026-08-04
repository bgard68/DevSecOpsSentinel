using DevSecOpsSentinel.Application;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace DevSecOpsSentinel.Api.Integration.Tests;

public sealed class ApiFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(
        IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.ConfigureAppConfiguration(
            (_, configuration) =>
            {
                configuration.AddInMemoryCollection(
                    new Dictionary<string, string?>
                    {
                        ["OpenAI:Mode"] = "Mock",
                        ["OpenAI:ApiKey"] = string.Empty,
                        ["OpenAI:Model"] = "gpt-5-mini",
                        ["GitHub:Enabled"] = "false",
                        ["GitHub:ResolveActionReferences"] = "false",
                        ["GitHub:AppId"] = "0",
                        ["GitHub:InstallationId"] = "0",
                        ["GitHub:PrivateKeyPath"] = string.Empty,
                        ["GitHub:AllowedRepositories:0"] = null,
                        ["Security:Mode"] = "Disabled",
                        ["Security:ApiKey"] = string.Empty
                    });
            });

        builder.ConfigureServices(services =>
        {
            services.RemoveAll<
                IWorkflowActionReferenceResolver>();

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
