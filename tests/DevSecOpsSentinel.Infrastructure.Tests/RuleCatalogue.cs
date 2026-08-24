using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Infrastructure.Rules;

namespace DevSecOpsSentinel.Infrastructure.Tests;

/// <summary>
/// Every rule the API registers, in one place.
///
/// Duplicated lists drift: a rule added to the application and not to a test's
/// private copy is simply never exercised, and nothing says so.
///
/// That copy is now gone. This delegates to the same discovery the composition
/// root uses, so "every rule the API registers" is true by construction rather
/// than by remembering.
/// </summary>
internal static class RuleCatalogue
{
    public static IReadOnlyList<IWorkflowSecurityRule> All() => RuleDiscovery.All();
}
