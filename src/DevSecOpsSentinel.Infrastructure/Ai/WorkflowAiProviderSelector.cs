using DevSecOpsSentinel.Application;

namespace DevSecOpsSentinel.Infrastructure.Ai;

/// <summary>
/// Picks the provider for a single request.
///
/// The provider used to be chosen once at startup, which meant the deployment
/// had one AI mode for everyone. That is fine while every caller has to present
/// a key, and wrong the moment anyone can reach the endpoint without one:
/// a deployment configured Live would have spent credits for anonymous
/// visitors.
///
/// So the configured provider is what an identified caller gets, and everyone
/// else gets Mock. Anonymous callers are not refused - they receive a complete,
/// correctly labelled explanation that reached nothing.
/// </summary>
public sealed class WorkflowAiProviderSelector(
    IWorkflowAiProvider configuredProvider,
    MockWorkflowAiProvider mockProvider) : IWorkflowAiProviderSelector
{
    public IWorkflowAiProvider Select(AiCallerAccess access) =>
        access == AiCallerAccess.Configured
            ? configuredProvider
            : mockProvider;
}
