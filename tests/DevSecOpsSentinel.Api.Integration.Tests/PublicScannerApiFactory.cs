using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace DevSecOpsSentinel.Api.Integration.Tests;

/// <summary>
/// Security:Mode = Public. The deterministic scanner is open; the key still
/// guards GitHub, and still decides whether the configured AI provider is used.
///
/// The configured provider is replaced with a stub that reports a mode of its
/// own. That is what makes the routing observable: a request served by the stub
/// and a request served by Mock are distinguishable in the response, without
/// the test needing a real OpenAI call or a network at all.
/// </summary>
public sealed class PublicScannerApiFactory :
    WebApplicationFactory<Program>
{
    public const string ValidApiKey =
        "public-mode-key-1234567890-abcdefghijklmnopqrstuvwxyz";

    /// <summary>Mode reported by the stub standing in for the configured provider.</summary>
    public const string ConfiguredProviderMode = "StubConfigured";

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.ConfigureAppConfiguration((_, configuration) =>
        {
            configuration.AddInMemoryCollection(
                new Dictionary<string, string?>
                {
                    ["OpenAI:Mode"] = "Live",
                    ["OpenAI:ApiKey"] = "not-used-the-provider-is-stubbed",
                    ["OpenAI:Model"] = "gpt-5-mini",
                    ["GitHub:Enabled"] = "false",
                    ["GitHub:ResolveActionReferences"] = "false",
                    ["GitHub:AppId"] = "0",
                    ["GitHub:InstallationId"] = "0",
                    ["GitHub:PrivateKeyPath"] = string.Empty,
                    ["GitHub:AllowedRepositories:0"] = null,
                    ["Security:Mode"] = "Public",
                    ["Security:ApiKey"] = ValidApiKey,
                    ["Security:HeaderName"] = "X-API-Key"
                });
        });

        builder.ConfigureServices(services =>
        {
            services.RemoveAll<IWorkflowActionReferenceResolver>();
            services.AddSingleton<
                IWorkflowActionReferenceResolver,
                StubActionReferenceResolver>();

            services.RemoveAll<IWorkflowAiProvider>();
            services.AddSingleton<IWorkflowAiProvider, StubConfiguredProvider>();
        });
    }

    private sealed class StubConfiguredProvider : IWorkflowAiProvider
    {
        public Task<WorkflowAiExplanation> ExplainAsync(
            WorkflowAnalysisResult analysis,
            string sanitizedContent,
            CancellationToken cancellationToken) =>
            Task.FromResult(new WorkflowAiExplanation(
                "Stub summary.",
                [],
                "Stub next step.",
                [],
                true,
                ConfiguredProviderMode));
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
