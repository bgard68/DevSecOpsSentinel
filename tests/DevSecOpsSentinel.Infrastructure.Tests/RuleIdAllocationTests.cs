using DevSecOpsSentinel.Application;

namespace DevSecOpsSentinel.Infrastructure.Tests;

/// <summary>
/// Rule ids have to be unique across everything that issues one — not just
/// across the rules.
///
/// Every existing id test enumerates <see cref="RuleCatalogue"/>, which is
/// reflection over <c>IWorkflowSecurityRule</c>. GHA012 is issued by
/// <see cref="WorkflowAnalysisService"/> against the acceptance mechanism and
/// implements no rule, so it is invisible to all of them. A rule was duly
/// written against GHA012 on 2026-10-29 and the whole suite passed; the
/// collision was caught by a sentence in rules.md, which is not a test.
///
/// An id is effectively public API — acceptance directives are written against
/// it and cannot be renumbered afterwards — so a duplicate is not a cosmetic
/// problem: two different findings would answer to one directive.
/// </summary>
public sealed class RuleIdAllocationTests
{
    [Fact]
    public void RuleIds_DoNotCollideWithIdsIssuedOutsideTheRules()
    {
        string[] colliding =
        [
            .. RuleCatalogue.All()
                .Select(rule => rule.RuleId)
                .Where(id => id == WorkflowAnalysisService.StaleSuppressionRuleId)
        ];

        Assert.True(
            colliding.Length == 0,
            $"{WorkflowAnalysisService.StaleSuppressionRuleId} is already issued by " +
            "WorkflowAnalysisService for a stale acceptance directive, and a rule now " +
            "claims it too. Give the rule the next unissued id - reflection over the " +
            "rules cannot see this one, so nothing else in the suite will tell you.");
    }

    [Fact]
    public void NextFreeRuleId_IsHigherThanEveryIssuedId()
    {
        // Documents the allocation itself: the next rule starts after the highest
        // id anyone issues, rules and non-rules alike. Written as an assertion so
        // the number in rules.md cannot quietly fall behind the code.
        int highestRule = RuleCatalogue.All()
            .Select(rule => Number(rule.RuleId))
            .Max();

        int staleSuppression = Number(WorkflowAnalysisService.StaleSuppressionRuleId);

        Assert.True(
            highestRule > staleSuppression,
            $"The highest rule id (GHA{highestRule:D3}) now sits below the stale-suppression " +
            $"id (GHA{staleSuppression:D3}). A new rule must take an id above every issued " +
            "one, so this ordering is what keeps the next allocation obvious.");
    }

    private static int Number(string ruleId) =>
        int.Parse(ruleId.AsSpan("GHA".Length));
}
