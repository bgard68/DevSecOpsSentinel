using DevSecOpsSentinel.Domain;
using DevSecOpsSentinel.Infrastructure;
using DevSecOpsSentinel.Infrastructure.Rules;

namespace DevSecOpsSentinel.Infrastructure.Tests;

public sealed class SecurityRuleTests
{
    private readonly WorkflowParser _parser = new();

    [Fact]
    public void Vulnerable_workflow_triggers_expected_rules()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on:",
            "  pull_request_target:",
            "permissions: write-all",
            "jobs:",
            "  build:",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - uses: actions/checkout@v4"
        ]));

        Assert.Single(new UnpinnedActionRule().Evaluate(workflow));
        Assert.Single(new ExcessivePermissionsRule().Evaluate(workflow));
        Assert.Single(new MissingTimeoutRule().Evaluate(workflow));
        Assert.Single(new UnsafePullRequestTargetRule().Evaluate(workflow));
    }

    [Fact]
    public void Hardened_workflow_has_no_findings()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on:",
            "  push:",
            "permissions: read-all",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - uses: actions/checkout@eef61447b4ff0ce0c2c1d7f3f76b1d6d7e3c2f55"
        ]));

        Assert.Empty(new UnpinnedActionRule().Evaluate(workflow));
        Assert.Empty(new ExcessivePermissionsRule().Evaluate(workflow));
        Assert.Empty(new MissingTimeoutRule().Evaluate(workflow));
        Assert.Empty(new UnsafePullRequestTargetRule().Evaluate(workflow));
    }

    private ParsedWorkflow Parse(string content)
    {
        var result = _parser.Parse(new WorkflowDocument("workflow.yml", content));
        Assert.True(result.IsValid);
        return Assert.IsType<ParsedWorkflow>(result.Workflow);
    }
}
