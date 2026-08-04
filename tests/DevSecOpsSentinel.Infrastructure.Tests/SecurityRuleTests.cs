using DevSecOpsSentinel.Application;
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

        Assert.Single(
            new UnpinnedActionRule().Evaluate(workflow));

        Assert.Single(
            new ExcessivePermissionsRule().Evaluate(workflow));

        Assert.Single(
            new MissingTimeoutRule().Evaluate(workflow));

        Assert.Single(
            new UnsafePullRequestTargetRule().Evaluate(workflow));
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

        Assert.Empty(
            new UnpinnedActionRule().Evaluate(workflow));

        Assert.Empty(
            new ExcessivePermissionsRule().Evaluate(workflow));

        Assert.Empty(
            new MissingTimeoutRule().Evaluate(workflow));

        Assert.Empty(
            new UnsafePullRequestTargetRule().Evaluate(workflow));
    }

    [Fact]
    public void Uses_text_inside_literal_run_block_is_not_an_action()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Script",
            "on:",
            "  push:",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - name: Inspect text",
            "        run: |",
            "          echo 'uses: actions/checkout@v4'",
            "          uses: actions/setup-node@v4"
        ]));

        Assert.Empty(
            new UnpinnedActionRule().Evaluate(workflow));
    }

    [Fact]
    public void Uses_text_inside_folded_run_block_is_not_an_action()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Script",
            "on:",
            "  push:",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - name: Inspect text",
            "        run: >-",
            "          echo uses:",
            "          actions/checkout@v4"
        ]));

        Assert.Empty(
            new UnpinnedActionRule().Evaluate(workflow));
    }

    [Fact]
    public void Real_action_after_run_block_is_still_evaluated()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Script",
            "on:",
            "  push:",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - name: Inspect text",
            "        run: |",
            "          uses: actions/setup-node@v4",
            "      - uses: actions/checkout@v4"
        ]));

        WorkflowFinding finding = Assert.Single(
            new UnpinnedActionRule().Evaluate(workflow));

        Assert.Equal(12, finding.LineNumber);
    }

    [Fact]
    public async Task Patch_generator_never_rewrites_run_block_content()
    {
        string content = string.Join('\n',
        [
            "name: Script",
            "on:",
            "  push:",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - name: Inspect text",
            "        run: |",
            "          uses: actions/setup-node@v4",
            "      - uses: actions/checkout@v4"
        ]);

        ParsedWorkflow workflow = Parse(content);

        IReadOnlyList<WorkflowFinding> findings =
            new UnpinnedActionRule().Evaluate(workflow);

        WorkflowPatch patch =
            await new WorkflowPatchGenerator(
                _parser,
                CreateRules(),
                new StubActionReferenceResolver(
                    "1111111111111111111111111111111111111111"))
                .GenerateAsync(
                    workflow,
                    findings,
                    CancellationToken.None);

        Assert.Contains(
            "          uses: actions/setup-node@v4",
            patch.ProposedContent,
            StringComparison.Ordinal);

        Assert.Contains(
            "- uses: actions/checkout@1111111111111111111111111111111111111111",
            patch.ProposedContent,
            StringComparison.Ordinal);

        Assert.Single(patch.AppliedRuleIds);
        Assert.Contains("GHA001", patch.AppliedRuleIds);
    }

    [Fact]
    public void Workflow_level_permissions_mapping_detects_write_entry()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on:",
            "  push:",
            "permissions:",
            "  contents: read",
            "  pull-requests: write",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest"
        ]));

        WorkflowFinding finding = Assert.Single(
            new ExcessivePermissionsRule().Evaluate(workflow));

        Assert.Equal(6, finding.LineNumber);
        Assert.False(finding.IsAutomaticallyFixable);
    }

    [Fact]
    public void Job_level_permissions_mapping_detects_write_entry()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on:",
            "  push:",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    permissions:",
            "      contents: read",
            "      packages: write",
            "    runs-on: ubuntu-latest"
        ]));

        WorkflowFinding finding = Assert.Single(
            new ExcessivePermissionsRule().Evaluate(workflow));

        Assert.Equal(9, finding.LineNumber);
        Assert.False(finding.IsAutomaticallyFixable);
    }

    [Fact]
    public void Unrelated_write_values_are_not_permissions_findings()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on:",
            "  push:",
            "permissions:",
            "  contents: read",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - name: Configure",
            "        with:",
            "          mode: write"
        ]));

        Assert.Empty(
            new ExcessivePermissionsRule().Evaluate(workflow));
    }

    [Fact]
    public void Commented_write_text_is_not_a_permissions_finding()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on:",
            "  push:",
            "permissions:",
            "  contents: read",
            "  # packages: write",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest"
        ]));

        Assert.Empty(
            new ExcessivePermissionsRule().Evaluate(workflow));
    }

    [Fact]
    public void Inline_write_all_is_detected_and_remains_auto_fixable()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on:",
            "  push:",
            "permissions: write-all # intentionally broad",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest"
        ]));

        WorkflowFinding finding = Assert.Single(
            new ExcessivePermissionsRule().Evaluate(workflow));

        Assert.Equal(4, finding.LineNumber);
        Assert.True(finding.IsAutomaticallyFixable);
    }


    [Fact]
    public async Task Patch_is_valid_only_when_applied_findings_are_removed()
    {
        string content = string.Join('\n',
        [
            "name: Build",
            "on:",
            "  push:",
            "permissions: write-all",
            "jobs:",
            "  build:",
            "    runs-on: ubuntu-latest"
        ]);

        ParsedWorkflow workflow = Parse(content);
        IReadOnlyList<IWorkflowSecurityRule> rules = CreateRules();

        WorkflowFinding[] findings = rules
            .SelectMany(rule => rule.Evaluate(workflow))
            .ToArray();

        WorkflowPatch patch =
            await new WorkflowPatchGenerator(
                _parser,
                rules,
                new StubActionReferenceResolver(
                    "1111111111111111111111111111111111111111"))
                .GenerateAsync(
                    workflow,
                    findings,
                    CancellationToken.None);

        Assert.True(patch.ProposedContentIsValid);
        Assert.Contains("GHA002", patch.AppliedRuleIds);
        Assert.Contains(
            "permissions: read-all",
            patch.ProposedContent,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Patch_is_invalid_when_remediation_introduces_a_new_finding()
    {
        string content = string.Join('\n',
        [
            "name: Build",
            "on:",
            "  push:",
            "permissions: write-all",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest"
        ]);

        ParsedWorkflow workflow = Parse(content);

        IWorkflowSecurityRule[] rules =
        [
            new ExcessivePermissionsRule(),
            new ReadAllRegressionRule()
        ];

        WorkflowFinding[] findings = rules
            .SelectMany(rule => rule.Evaluate(workflow))
            .ToArray();

        WorkflowPatch patch =
            await new WorkflowPatchGenerator(
                _parser,
                rules,
                new StubActionReferenceResolver(
                    "1111111111111111111111111111111111111111"))
                .GenerateAsync(
                    workflow,
                    findings,
                    CancellationToken.None);

        Assert.False(patch.ProposedContentIsValid);
    }

    private static IReadOnlyList<IWorkflowSecurityRule> CreateRules() =>
    [
        new UnpinnedActionRule(),
        new ExcessivePermissionsRule(),
        new MissingTimeoutRule(),
        new UnsafePullRequestTargetRule()
    ];

    private sealed class ReadAllRegressionRule :
        IWorkflowSecurityRule
    {
        public string RuleId => "TEST001";
        public string Title => "Remediation regression";
        public WorkflowSeverity Severity => WorkflowSeverity.High;

        public IReadOnlyList<WorkflowFinding> Evaluate(
            ParsedWorkflow workflow) =>
            workflow.Lines
                .Where(line => line.Text.Equals(
                    "permissions: read-all",
                    StringComparison.OrdinalIgnoreCase))
                .Select(line => new WorkflowFinding(
                    RuleId,
                    Severity,
                    Title,
                    "The proposed remediation introduced a regression.",
                    line.Number,
                    "Do not introduce this value.",
                    false))
                .ToArray();
    }


    [Fact]
    public async Task Unresolved_action_reference_is_not_rewritten_or_counted_as_applied()
    {
        string content = string.Join('\n',
        [
            "name: Build",
            "on:",
            "  push:",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - uses: actions/checkout@v4"
        ]);

        ParsedWorkflow workflow = Parse(content);
        IReadOnlyList<IWorkflowSecurityRule> rules = CreateRules();

        WorkflowFinding[] findings = rules
            .SelectMany(rule => rule.Evaluate(workflow))
            .ToArray();

        WorkflowPatch patch =
            await new WorkflowPatchGenerator(
                _parser,
                rules,
                new StubActionReferenceResolver(null))
                .GenerateAsync(
                    workflow,
                    findings,
                    CancellationToken.None);

        Assert.DoesNotContain(
            "0000000000000000000000000000000000000000",
            patch.ProposedContent,
            StringComparison.Ordinal);

        Assert.Contains(
            "actions/checkout@v4",
            patch.ProposedContent,
            StringComparison.Ordinal);

        Assert.DoesNotContain(
            "GHA001",
            patch.AppliedRuleIds);
    }

    private sealed class StubActionReferenceResolver(
        string? resolvedSha)
        : IWorkflowActionReferenceResolver
    {
        public Task<string?> ResolveCommitShaAsync(
            string actionReference,
            CancellationToken cancellationToken) =>
            Task.FromResult(resolvedSha);
    }

    private ParsedWorkflow Parse(string content)
    {
        WorkflowParseResult result = _parser.Parse(
            new WorkflowDocument("workflow.yml", content));

        Assert.True(result.IsValid);
        return Assert.IsType<ParsedWorkflow>(result.Workflow);
    }
}
