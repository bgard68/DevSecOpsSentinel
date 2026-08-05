using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Tests;

/// <summary>
/// The severity scale and the rules that populate it have to agree.
///
/// <see cref="WorkflowSeverity"/> documents the invariant — every member is
/// produced by at least one rule — and nothing enforced it. Low was produced by
/// none, so the client rendered a category that could never fill and the exports
/// carried a level that never appeared. The same defect had already been fixed
/// once by deleting Informational; deleting a value is not a habit, so this
/// asserts the rule instead.
/// </summary>
public sealed class SeverityCoverageTests
{
    [Fact]
    public void Every_severity_is_produced_by_at_least_one_rule()
    {
        HashSet<WorkflowSeverity> declared =
        [
            .. RuleCatalogue.All().Select(rule => rule.Severity)
        ];

        WorkflowSeverity[] unused = Enum.GetValues<WorkflowSeverity>()
            .Where(severity => !declared.Contains(severity))
            .ToArray();

        Assert.True(
            unused.Length == 0,
            "No rule produces: " + string.Join(", ", unused) +
            ". Either assign a rule to it, or remove it from WorkflowSeverity - " +
            "a level nothing emits is a category the client can never populate.");
    }

    [Fact]
    public void Every_rule_declares_a_severity_the_scale_defines()
    {
        // The other direction: a rule cannot report a value outside the scale,
        // which would sort unpredictably and serialise as a number.
        foreach (IWorkflowSecurityRule rule in RuleCatalogue.All())
        {
            Assert.True(
                Enum.IsDefined(rule.Severity),
                $"{rule.RuleId} declares severity {(int)rule.Severity}, which is not on the scale.");
        }
    }

    [Fact]
    public void Rule_identifiers_are_unique()
    {
        // Two rules sharing an id would silently merge in any report grouped by
        // it, and the AI constraint check compares rule-id sets for equality.
        string[] duplicates = RuleCatalogue.All()
            .GroupBy(rule => rule.RuleId)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)
            .ToArray();

        Assert.True(
            duplicates.Length == 0,
            "Duplicate rule ids: " + string.Join(", ", duplicates));
    }
}
