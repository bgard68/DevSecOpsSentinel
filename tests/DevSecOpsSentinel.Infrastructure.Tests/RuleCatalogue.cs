using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Infrastructure.Rules;

namespace DevSecOpsSentinel.Infrastructure.Tests;

/// <summary>
/// Every rule the API registers, in one place.
///
/// Duplicated lists drift: a rule added to the application and not to a test's
/// private copy is simply never exercised, and nothing says so.
/// </summary>
internal static class RuleCatalogue
{
    public static IReadOnlyList<IWorkflowSecurityRule> All() =>
    [
        new UnpinnedActionRule(),
        new ExcessivePermissionsRule(),
        new MissingTimeoutRule(),
        new UnsafePullRequestTargetRule(),
        new ScriptInjectionRule(),
        new PersistedCredentialsRule(),
        new UntrustedCheckoutRule(),
        new InheritedSecretsRule(),
        new UndeclaredPermissionsRule(),
        new SelfHostedRunnerRule(),
        new ArtifactPoisoningRule()
    ];
}
