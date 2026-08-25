using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;
using DevSecOpsSentinel.Infrastructure.Rules;

namespace DevSecOpsSentinel.Infrastructure.Tests;

/// <summary>
/// What a rule accepted, said out loud.
///
/// Establishing need removed findings, which left silence where the reasoning
/// used to be: a workflow reported clean gave no way to tell "the rule checked
/// this grant and accepted it" from "the rule never looked". These carry the
/// reason without becoming findings, because the client reads any finding as
/// action required and a correct workflow must not read that way.
/// </summary>
public sealed class AcknowledgementTests
{
    private readonly WorkflowParser _parser = new();

    [Fact]
    public void An_accepted_grant_names_the_action_that_requires_it()
    {
        ParsedWorkflow workflow = Parse(
            "name: CodeQL",
            "on: push",
            "jobs:",
            "  analyze:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 20",
            "    permissions:",
            "      security-events: write",
            "    steps:",
            "      - uses: github/codeql-action/analyze@v3");

        ExcessivePermissionsRule rule = new();

        Assert.Empty(rule.Evaluate(workflow));

        WorkflowAcknowledgement accepted = Assert.Single(rule.Acknowledge(workflow));
        Assert.Equal("GHA002", accepted.RuleId);
        Assert.Equal(8, accepted.LineNumber);
        Assert.Contains("security-events: write is required", accepted.Title);
        Assert.Contains("github/codeql-action/analyze", accepted.Detail);
    }

    [Fact]
    public void A_grant_that_is_reported_is_not_also_acknowledged()
    {
        // The two lists are exclusive: a scope cannot be both the problem and
        // the thing that was fine.
        ParsedWorkflow workflow = Parse(
            "name: Build",
            "on: push",
            "jobs:",
            "  build:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 10",
            "    permissions:",
            "      contents: write",
            "    steps:",
            "      - uses: actions/checkout@v4");

        ExcessivePermissionsRule rule = new();

        Assert.Single(rule.Evaluate(workflow));
        Assert.Empty(rule.Acknowledge(workflow));
    }

    [Fact]
    public void A_persisted_credential_that_gets_pushed_with_is_acknowledged()
    {
        ParsedWorkflow workflow = Parse(
            "name: Release",
            "on: push",
            "jobs:",
            "  release:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 10",
            "    steps:",
            "      - uses: actions/checkout@v4",
            "      - name: Tag",
            "        run: git push origin v1.0.0");

        PersistedCredentialsRule rule = new();

        Assert.Empty(rule.Evaluate(workflow));

        WorkflowAcknowledgement accepted = Assert.Single(rule.Acknowledge(workflow));
        Assert.Equal("GHA006", accepted.RuleId);
        Assert.Contains("pushes with the job token", accepted.Detail);
    }

    [Fact]
    public void A_checkout_that_is_reported_is_not_also_acknowledged()
    {
        ParsedWorkflow workflow = Parse(
            "name: Build",
            "on: push",
            "jobs:",
            "  build:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 10",
            "    steps:",
            "      - uses: actions/checkout@v4",
            "      - name: Build",
            "        run: dotnet build");

        PersistedCredentialsRule rule = new();

        Assert.Single(rule.Evaluate(workflow));
        Assert.Empty(rule.Acknowledge(workflow));
    }

    [Fact]
    public void Rules_that_never_suppress_anything_acknowledge_nothing()
    {
        // The interface defaults, so the other rules needed no opinion; this
        // pins that the default is empty rather than a surprise.
        ParsedWorkflow workflow = Parse(
            "name: Build",
            "on: push",
            "jobs:",
            "  build:",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - uses: actions/checkout@v4");

        foreach (IWorkflowSecurityRule rule in RuleCatalogue.All())
        {
            if (rule is ExcessivePermissionsRule or PersistedCredentialsRule)
            {
                continue;
            }

            Assert.Empty(rule.Acknowledge(workflow));
        }
    }

    private ParsedWorkflow Parse(params string[] lines)
    {
        WorkflowParseResult result = _parser.Parse(
            new WorkflowDocument("workflow.yml", string.Join('\n', lines)));

        Assert.True(result.IsValid, string.Join("; ", result.Errors));
        return Assert.IsType<ParsedWorkflow>(result.Workflow);
    }
}
