using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Infrastructure.GitHub;

namespace DevSecOpsSentinel.Infrastructure.Rules.Fixes;

/// <summary>
/// Every fix in this assembly.
///
/// Listed rather than reflected, which is the opposite of <see cref="RuleDiscovery"/> and for
/// the reason stated there: a fix takes constructor arguments, so it cannot be activated
/// without them. Reflection would skip exactly the fixes that have dependencies and report
/// nothing, which is the silent failure that registry exists to avoid.
///
/// The drift risk a hand-written list carries is answered by a test asserting that every
/// automatically fixable rule has a fix registered here, so a rule marked fixable with no
/// fix fails the build rather than quietly proposing no patch.
/// </summary>
public static class FixDiscovery
{
    public static IReadOnlyList<IWorkflowFix> All(
        IWorkflowActionReferenceResolver actionReferenceResolver,
        GitHubOptions gitHubOptions) =>
    [
        new UnpinnedActionFix(actionReferenceResolver, gitHubOptions),
        new ExcessivePermissionsFix(),
        new MissingTimeoutFix()
    ];
}
