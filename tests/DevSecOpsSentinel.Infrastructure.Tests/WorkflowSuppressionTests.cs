using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Tests;

/// <summary>
/// Accepting a finding in the workflow that carries it.
///
/// The mechanism is a judgement recorder, not a mute button, so what is asserted
/// here is mostly what it refuses to do: honour an acceptance with no reason,
/// let one acceptance cover a second finding elsewhere in the file, or stay
/// quiet once an acceptance has outlived the finding it was written about. That
/// last one is what stops a suppression list rotting into decoration.
/// </summary>
public sealed class WorkflowSuppressionTests
{
    private static readonly WorkflowParser Parser = new();

    private static WorkflowSuppressions Read(params string[] lines)
    {
        WorkflowParseResult result = Parser.Parse(
            new WorkflowDocument("workflow.yml", string.Join('\n', lines)));

        Assert.True(result.IsValid, string.Join("; ", result.Errors));
        return WorkflowSuppressions.Read(Assert.IsType<ParsedWorkflow>(result.Workflow));
    }

    private static WorkflowFinding Finding(string ruleId, int line) =>
        new(ruleId, WorkflowSeverity.High, "t", "d", line, "r", false);

    [Fact]
    public void An_acceptance_above_a_line_is_about_that_line()
    {
        WorkflowSuppressions suppressions = Read(
            "name: Prune",
            "on: workflow_dispatch",
            "jobs:",
            "  prune:",
            "    runs-on: ubuntu-latest",
            "    permissions:",
            "      # sentinel:accept GHA002 - deleting a run has no narrower grant",
            "      actions: write",
            "    steps:",
            "      - run: gh api -X DELETE /repos/o/r/actions/runs/1");

        WorkflowSuppressions.Suppression entry = Assert.Single(suppressions.Entries);
        Assert.Equal("GHA002", entry.RuleId);
        Assert.Equal(8, entry.Line);          // the grant, not the comment
        Assert.Equal(7, entry.DirectiveLine); // the comment, for reporting
        Assert.Equal("deleting a run has no narrower grant", entry.Reason);

        Assert.NotNull(suppressions.For(Finding("GHA002", 8)));
    }

    [Fact]
    public void A_trailing_acceptance_is_about_its_own_line()
    {
        WorkflowSuppressions suppressions = Read(
            "name: Prune",
            "on: workflow_dispatch",
            "jobs:",
            "  prune:",
            "    runs-on: ubuntu-latest",
            "    permissions:",
            "      actions: write # sentinel:accept GHA002 - no narrower grant exists",
            "    steps:",
            "      - run: echo hi");

        WorkflowSuppressions.Suppression entry = Assert.Single(suppressions.Entries);
        Assert.Equal(7, entry.Line);
        Assert.Equal("no narrower grant exists", entry.Reason);
    }

    [Fact]
    public void An_acceptance_without_a_reason_is_refused()
    {
        // The whole value is forcing the thinking to be written down. A bare
        // marker records that someone wanted the finding gone, not that anyone
        // considered it.
        WorkflowSuppressions suppressions = Read(
            "name: Prune",
            "on: push",
            "jobs:",
            "  prune:",
            "    runs-on: ubuntu-latest",
            "    permissions:",
            "      # sentinel:accept GHA002",
            "      actions: write",
            "    steps:",
            "      - run: echo hi");

        Assert.Empty(suppressions.Entries);
        Assert.Equal(7, Assert.Single(suppressions.WithoutReason));
        Assert.Null(suppressions.For(Finding("GHA002", 8)));
    }

    [Fact]
    public void An_acceptance_covers_one_line_not_the_whole_file()
    {
        WorkflowSuppressions suppressions = Read(
            "name: Two",
            "on: push",
            "jobs:",
            "  a:",
            "    runs-on: ubuntu-latest",
            "    permissions:",
            "      # sentinel:accept GHA002 - this one is required",
            "      actions: write",
            "    steps:",
            "      - run: echo hi",
            "  b:",
            "    runs-on: ubuntu-latest",
            "    permissions:",
            "      contents: write",
            "    steps:",
            "      - run: echo hi");

        Assert.NotNull(suppressions.For(Finding("GHA002", 8)));

        // The second grant was never considered, so it is not covered.
        Assert.Null(suppressions.For(Finding("GHA002", 14)));
    }

    [Fact]
    public void An_acceptance_covers_only_the_rule_it_names()
    {
        WorkflowSuppressions suppressions = Read(
            "name: One",
            "on: push",
            "jobs:",
            "  a:",
            "    runs-on: ubuntu-latest",
            "    permissions:",
            "      # sentinel:accept GHA002 - considered",
            "      actions: write",
            "    steps:",
            "      - run: echo hi");

        Assert.NotNull(suppressions.For(Finding("GHA002", 8)));
        Assert.Null(suppressions.For(Finding("GHA006", 8)));
    }

    [Fact]
    public void An_acceptance_that_outlived_its_finding_is_reported()
    {
        WorkflowSuppressions suppressions = Read(
            "name: Fixed",
            "on: push",
            "jobs:",
            "  a:",
            "    runs-on: ubuntu-latest",
            "    permissions:",
            "      # sentinel:accept GHA002 - was required, then it was not",
            "      contents: read",
            "    steps:",
            "      - run: echo hi");

        // Nothing reports GHA002 here any more, so the comment now claims a
        // consideration of something that is not there.
        WorkflowSuppressions.Suppression stale = Assert.Single(suppressions.Stale([]));
        Assert.Equal("GHA002", stale.RuleId);
        Assert.Equal(7, stale.DirectiveLine);
    }

    [Fact]
    public void An_acceptance_that_still_matches_is_not_stale()
    {
        WorkflowSuppressions suppressions = Read(
            "name: Live",
            "on: push",
            "jobs:",
            "  a:",
            "    runs-on: ubuntu-latest",
            "    permissions:",
            "      # sentinel:accept GHA002 - still required",
            "      actions: write",
            "    steps:",
            "      - run: echo hi");

        Assert.Empty(suppressions.Stale([Finding("GHA002", 8)]));
    }

    [Fact]
    public void An_unrelated_comment_is_not_a_directive()
    {
        WorkflowSuppressions suppressions = Read(
            "name: Plain",
            "on: push",
            "jobs:",
            "  a:",
            "    runs-on: ubuntu-latest",
            "    permissions:",
            "      # actions: write is needed to prune runs. GHA002 explains why.",
            "      actions: write",
            "    steps:",
            "      - run: echo hi");

        Assert.Empty(suppressions.Entries);
        Assert.Empty(suppressions.WithoutReason);
    }
}
