using DevSecOpsSentinel.Application;

namespace DevSecOpsSentinel.Infrastructure.Rules;

/// <summary>
/// Every security rule in this assembly, found rather than listed.
///
/// The list used to be written out three times — once in the composition root, once in the
/// tests, once in the eval — and a rule added to two of them would simply never run in the
/// third, with nothing to say so. A hand-maintained registry is the one thing certain to
/// drift, because forgetting it produces no error, only silence.
///
/// Ordered by rule id so registration order is the order a reader expects (GHA001 first) and
/// does not depend on the order the runtime happens to return types in.
/// </summary>
public static class RuleDiscovery
{
    /// <summary>
    /// A fresh instance per call. Rules hold no state between evaluations, but handing out a
    /// shared array would let a caller's edit reach every other caller.
    /// </summary>
    public static IReadOnlyList<IWorkflowSecurityRule> All() =>
    [
        .. typeof(RuleDiscovery).Assembly
            .GetTypes()
            .Where(type => typeof(IWorkflowSecurityRule).IsAssignableFrom(type))
            .Where(type => type is { IsAbstract: false, IsInterface: false })
            // A rule needing constructor arguments cannot be discovered this way. There is no
            // such rule today; if one is added, it needs registering explicitly and this
            // filter keeps it from being silently skipped as an activation failure.
            .Where(type => type.GetConstructor(Type.EmptyTypes) is not null)
            .Select(Activator.CreateInstance)
            .Cast<IWorkflowSecurityRule>()
            .OrderBy(rule => rule.RuleId, StringComparer.Ordinal)
    ];
}
