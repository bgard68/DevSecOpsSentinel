using System.Globalization;
using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Tests;

/// <summary>
/// The same workflow analysed on two machines has to produce the same findings.
///
/// Case-insensitive matching without <c>CultureInvariant</c> folds case using
/// the current culture, and Turkish is the classic counterexample: uppercase I
/// lowercases to a dotless i, so a pattern containing an i stops matching text
/// that differs only in case. Every pattern here contains one - "sentinel",
/// "uses" - so a deployment in tr-TR would have quietly analysed the same file
/// differently from one in en-US.
///
/// Determinism is the property this project sells. It has to hold across
/// machines, not only across runs on one.
///
/// Only the acceptance directive is exercised here, because it is the only
/// pattern whose case actually varies in practice. The others sit behind an
/// ordinal prefix check - UnpinnedActionRule matches "uses:" with
/// StringComparison.Ordinal before its regex runs - so their case folding
/// cannot be reached. They were pinned anyway: a guard that is unreachable
/// today is reachable the moment someone loosens the check in front of it.
/// </summary>
public sealed class CultureInvarianceTests
{
    private static readonly WorkflowParser Parser = new();

    /// <summary>Runs an assertion with the thread pinned to a culture.</summary>
    private static void InCulture(string name, Action assertion)
    {
        CultureInfo original = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = new CultureInfo(name);
            assertion();
        }
        finally
        {
            CultureInfo.CurrentCulture = original;
        }
    }

    private static ParsedWorkflow Parse(params string[] lines)
    {
        WorkflowParseResult result = Parser.Parse(
            new WorkflowDocument("workflow.yml", string.Join('\n', lines)));

        Assert.True(result.IsValid, string.Join("; ", result.Errors));
        return Assert.IsType<ParsedWorkflow>(result.Workflow);
    }

    [Theory]
    [InlineData("en-US")]
    [InlineData("tr-TR")]
    public void An_uppercased_acceptance_is_read_in_any_culture(string culture)
    {
        InCulture(culture, () =>
        {
            ParsedWorkflow workflow = Parse(
                "name: Prune",
                "on: workflow_dispatch",
                "jobs:",
                "  prune:",
                "    runs-on: ubuntu-latest",
                "    permissions:",
                "      # SENTINEL:ACCEPT GHA002 - no narrower grant exists",
                "      actions: write",
                "    steps:",
                "      - run: echo hi");

            WorkflowSuppressions.Suppression entry =
                Assert.Single(WorkflowSuppressions.Read(workflow).Entries);

            Assert.Equal("GHA002", entry.RuleId);
            Assert.Equal(8, entry.Line);
        });
    }

}
