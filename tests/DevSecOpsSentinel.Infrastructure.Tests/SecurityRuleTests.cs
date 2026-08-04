using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;
using DevSecOpsSentinel.Infrastructure;
using DevSecOpsSentinel.Infrastructure.GitHub;
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
                    "1111111111111111111111111111111111111111"),
                CreateGitHubOptions())
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
                    "1111111111111111111111111111111111111111"),
                CreateGitHubOptions())
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
                    "1111111111111111111111111111111111111111"),
                CreateGitHubOptions())
                .GenerateAsync(
                    workflow,
                    findings,
                    CancellationToken.None);

        Assert.False(patch.ProposedContentIsValid);
    }

    private static GitHubOptions CreateGitHubOptions() =>
        new()
        {
            ResolveActionReferences = true
        };

    private static IReadOnlyList<IWorkflowSecurityRule> CreateRules() =>
    [
        new UnpinnedActionRule(),
        new ExcessivePermissionsRule(),
        new MissingTimeoutRule(),
        new UnsafePullRequestTargetRule(),
        new ScriptInjectionRule(),
        new PersistedCredentialsRule(),
        new UntrustedCheckoutRule(),
        new InheritedSecretsRule(),
        new UndeclaredPermissionsRule(),
        new SelfHostedRunnerRule(),
        new ArtifactPoisoningRule()
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
    public async Task Action_reference_resolution_is_disabled_by_default()
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

        WorkflowPatch patch =
            await new WorkflowPatchGenerator(
                _parser,
                rules,
                new StubActionReferenceResolver(
                    "1111111111111111111111111111111111111111"),
                new GitHubOptions())
                .GenerateAsync(
                    workflow,
                    rules.SelectMany(rule => rule.Evaluate(workflow)).ToArray(),
                    CancellationToken.None);

        Assert.Contains(
            "actions/checkout@v4",
            patch.ProposedContent,
            StringComparison.Ordinal);
        Assert.DoesNotContain("GHA001", patch.AppliedRuleIds);
        Assert.Single(patch.ReferenceResolutionWarnings);
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
                new StubActionReferenceResolver(null),
                CreateGitHubOptions())
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
        public Task<ActionReferenceResolutionResult> ResolveAsync(
            string actionReference,
            CancellationToken cancellationToken) =>
            Task.FromResult(
                resolvedSha is null
                    ? new ActionReferenceResolutionResult(
                        ActionReferenceResolutionStatus.NotFound,
                        null,
                        "The reference was not found.")
                    : new ActionReferenceResolutionResult(
                        ActionReferenceResolutionStatus.Resolved,
                        resolvedSha,
                        "Resolved."));
    }

    [Theory]
    [InlineData("github.event.issue.title")]
    [InlineData("github.event.pull_request.title")]
    [InlineData("github.event.pull_request.head.ref")]
    [InlineData("github.event.comment.body")]
    [InlineData("github.event.head_commit.message")]
    [InlineData("github.head_ref")]
    public void Untrusted_expression_in_a_run_block_is_a_script_injection(
        string context)
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on:",
            "  pull_request:",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - name: Greet",
            "        run: |",
            $"          echo \"Thanks for ${{{{ {context} }}}}\""
        ]));

        WorkflowFinding finding = Assert.Single(
            new ScriptInjectionRule().Evaluate(workflow));

        Assert.Equal("GHA005", finding.RuleId);
        Assert.Equal(WorkflowSeverity.Critical, finding.Severity);
        Assert.Equal(11, finding.LineNumber);
        Assert.Contains(context, finding.Description, StringComparison.Ordinal);
        Assert.False(finding.IsAutomaticallyFixable);
    }

    [Fact]
    public void Untrusted_expression_in_a_single_line_run_is_detected()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on:",
            "  issues:",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - run: echo \"${{ github.event.issue.body }}\""
        ]));

        WorkflowFinding finding = Assert.Single(
            new ScriptInjectionRule().Evaluate(workflow));

        Assert.Equal(9, finding.LineNumber);
    }

    [Fact]
    public void Untrusted_expression_in_a_github_script_block_is_detected()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on:",
            "  issue_comment:",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - uses: actions/github-script@v7",
            "        with:",
            "          script: |",
            "            console.log(\"${{ github.event.comment.body }}\")"
        ]));

        Assert.Single(new ScriptInjectionRule().Evaluate(workflow));
    }

    [Fact]
    public void Trusted_expressions_in_a_run_block_are_not_reported()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on:",
            "  pull_request:",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - name: Report",
            "        run: |",
            "          echo \"${{ github.sha }}\"",
            "          echo \"${{ github.repository }}\"",
            "          echo \"${{ github.run_id }}\"",
            "          echo \"${{ secrets.GITHUB_TOKEN }}\""
        ]));

        Assert.Empty(new ScriptInjectionRule().Evaluate(workflow));
    }

    [Fact]
    public void Untrusted_expression_outside_a_script_body_is_not_reported()
    {
        // `if:` and `with:` values are evaluated by the expression engine, not
        // substituted into a shell, so they are not injection sinks.
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on:",
            "  pull_request:",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - name: Conditional",
            "        if: ${{ github.event.pull_request.title != '' }}",
            "        uses: actions/labeler@0000000000000000000000000000000000000000",
            "        with:",
            "          title: ${{ github.event.pull_request.title }}"
        ]));

        Assert.Empty(new ScriptInjectionRule().Evaluate(workflow));
    }

    [Fact]
    public void Bound_environment_variable_is_the_recommended_safe_form()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on:",
            "  pull_request:",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - name: Greet",
            "        env:",
            "          TITLE: ${{ github.event.pull_request.title }}",
            "        run: |",
            "          echo \"$TITLE\""
        ]));

        Assert.Empty(new ScriptInjectionRule().Evaluate(workflow));
    }

    [Fact]
    public void Script_block_content_is_still_excluded_from_yaml_lines()
    {
        // The parser must keep withholding script bodies from Lines, or the
        // unpinned-action and permissions rules regress to false positives.
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on:",
            "  push:",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - name: Text",
            "        run: |",
            "          uses: actions/checkout@v4",
            "          contents: write"
        ]));

        Assert.Empty(new UnpinnedActionRule().Evaluate(workflow));
        Assert.Empty(new ExcessivePermissionsRule().Evaluate(workflow));

        WorkflowScriptBlock block = Assert.Single(workflow.ScriptBlocks);
        Assert.Equal("run", block.Key);
        Assert.Equal(10, block.HeaderLine);
        Assert.Equal(2, block.Content.Count);
    }

    [Fact]
    public void Checkout_without_persist_credentials_uses_the_unsafe_default()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on:",
            "  push:",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - uses: actions/checkout@0000000000000000000000000000000000000000"
        ]));

        WorkflowFinding finding = Assert.Single(
            new PersistedCredentialsRule().Evaluate(workflow));

        Assert.Equal("GHA006", finding.RuleId);
        Assert.Equal(9, finding.LineNumber);
    }

    [Fact]
    public void Checkout_that_disables_persist_credentials_is_not_reported()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on:",
            "  push:",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - name: Checkout",
            "        uses: actions/checkout@0000000000000000000000000000000000000000",
            "        with:",
            "          persist-credentials: false"
        ]));

        Assert.Empty(new PersistedCredentialsRule().Evaluate(workflow));
    }

    [Fact]
    public void Persist_credentials_set_to_true_is_reported_at_its_own_line()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on:",
            "  push:",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - uses: actions/checkout@0000000000000000000000000000000000000000",
            "        with:",
            "          persist-credentials: true"
        ]));

        WorkflowFinding finding = Assert.Single(
            new PersistedCredentialsRule().Evaluate(workflow));

        Assert.Equal(11, finding.LineNumber);
    }

    [Fact]
    public void Non_checkout_actions_are_not_persist_credentials_findings()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on:",
            "  push:",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - uses: actions/setup-node@0000000000000000000000000000000000000000",
            "        with:",
            "          node-version: 22"
        ]));

        Assert.Empty(new PersistedCredentialsRule().Evaluate(workflow));
    }

    [Fact]
    public void Pull_request_target_checking_out_head_sha_is_critical()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Review",
            "on:",
            "  pull_request_target:",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - uses: actions/checkout@0000000000000000000000000000000000000000",
            "        with:",
            "          ref: ${{ github.event.pull_request.head.sha }}"
        ]));

        WorkflowFinding finding = Assert.Single(
            new UntrustedCheckoutRule().Evaluate(workflow));

        Assert.Equal("GHA007", finding.RuleId);
        Assert.Equal(WorkflowSeverity.Critical, finding.Severity);
        Assert.Equal(11, finding.LineNumber);
    }

    [Fact]
    public void Pull_request_target_without_an_untrusted_ref_is_not_reported()
    {
        // The trigger alone is GHA004's concern. Without a checkout of the
        // contributor's code there is no execution of untrusted input.
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Label",
            "on:",
            "  pull_request_target:",
            "jobs:",
            "  label:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - uses: actions/checkout@0000000000000000000000000000000000000000"
        ]));

        Assert.Empty(new UntrustedCheckoutRule().Evaluate(workflow));
    }

    [Fact]
    public void Untrusted_ref_under_the_safe_trigger_is_not_reported()
    {
        // pull_request already runs in the contributor's context without
        // secrets, so checking out their head is the normal, safe thing to do.
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on:",
            "  pull_request:",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - uses: actions/checkout@0000000000000000000000000000000000000000",
            "        with:",
            "          ref: ${{ github.event.pull_request.head.sha }}"
        ]));

        Assert.Empty(new UntrustedCheckoutRule().Evaluate(workflow));
    }

    [Fact]
    public void With_inputs_are_attributed_to_the_step_that_declares_them()
    {
        // Two checkout steps in one job: only the second disables the token.
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on:",
            "  push:",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - uses: actions/checkout@0000000000000000000000000000000000000000",
            "      - uses: actions/checkout@0000000000000000000000000000000000000000",
            "        with:",
            "          persist-credentials: false"
        ]));

        WorkflowFinding finding = Assert.Single(
            new PersistedCredentialsRule().Evaluate(workflow));

        Assert.Equal(9, finding.LineNumber);
    }

    [Fact]
    public void Flow_style_permissions_are_detected()
    {
        // Indentation matching only recognised a permissions: block followed by
        // indented entries, so this form was silently missed.
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on: push",
            "permissions: {contents: write, issues: read}",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest"
        ]));

        WorkflowFinding finding = Assert.Single(
            new ExcessivePermissionsRule().Evaluate(workflow));

        Assert.Equal(3, finding.LineNumber);
    }

    [Fact]
    public void Quoted_on_key_still_yields_triggers()
    {
        // Written this way to stop YAML 1.1 resolving `on` to the boolean true.
        // A prefix match on "on:" does not see it.
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Review",
            "'on':",
            "  pull_request_target:",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest"
        ]));

        Assert.Contains("pull_request_target", workflow.Triggers);
        Assert.Single(new UnsafePullRequestTargetRule().Evaluate(workflow));
    }

    [Fact]
    public void Trigger_written_as_a_flow_sequence_is_understood()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Review",
            "on: [push, pull_request_target]",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest"
        ]));

        Assert.Contains("pull_request_target", workflow.Triggers);
    }

    [Fact]
    public void Permission_value_followed_by_a_comment_is_still_a_grant()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on: push",
            "permissions:",
            "  contents: write # needed to push tags",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest"
        ]));

        Assert.Single(new ExcessivePermissionsRule().Evaluate(workflow));
    }

    [Fact]
    public void Malformed_yaml_is_rejected_rather_than_partially_analyzed()
    {
        // Returning findings from a document the parser could not read would
        // omit whatever the malformed region contained, which is the failure
        // mode a deterministic-first analyser cannot afford.
        WorkflowParseResult result = _parser.Parse(new WorkflowDocument(
            "workflow.yml",
            string.Join('\n',
            [
                "name: Build",
                "on: push",
                "jobs:",
                "  build:",
                "   runs-on: ubuntu-latest",
                "     timeout-minutes: 15"
            ])));

        Assert.False(result.IsValid);
        Assert.Contains(
            result.Errors,
            error => error.Contains("not well formed", StringComparison.Ordinal));
    }

    [Fact]
    public void Inputs_are_attributed_when_name_precedes_uses()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Review",
            "on:",
            "  pull_request_target:",
            "jobs:",
            "  build:",
            "    timeout-minutes: 15",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - name: Check out the contributor's branch",
            "        uses: actions/checkout@0000000000000000000000000000000000000000",
            "        with:",
            "          persist-credentials: false",
            "          ref: ${{ github.event.pull_request.head.sha }}"
        ]));

        // persist-credentials is honoured, so only the untrusted checkout fires.
        Assert.Empty(new PersistedCredentialsRule().Evaluate(workflow));

        WorkflowFinding finding = Assert.Single(
            new UntrustedCheckoutRule().Evaluate(workflow));

        Assert.Equal(13, finding.LineNumber);
    }

    [Fact]
    public void Reusable_workflow_call_inheriting_secrets_is_reported()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on: push",
            "permissions:",
            "  contents: read",
            "jobs:",
            "  call:",
            "    uses: bgard68/shared/.github/workflows/build.yml@main",
            "    secrets: inherit"
        ]));

        WorkflowFinding finding = Assert.Single(
            new InheritedSecretsRule().Evaluate(workflow));

        Assert.Equal("GHA008", finding.RuleId);
        Assert.Equal(8, finding.LineNumber);
    }

    [Fact]
    public void Named_secrets_on_a_reusable_call_are_not_reported()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on: push",
            "permissions:",
            "  contents: read",
            "jobs:",
            "  call:",
            "    uses: bgard68/shared/.github/workflows/build.yml@main",
            "    secrets:",
            "      TOKEN: ${{ secrets.BUILD_TOKEN }}"
        ]));

        Assert.Empty(new InheritedSecretsRule().Evaluate(workflow));
    }

    [Fact]
    public void Workflow_without_any_permissions_block_is_reported()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on: push",
            "jobs:",
            "  build:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 15"
        ]));

        WorkflowFinding finding = Assert.Single(
            new UndeclaredPermissionsRule().Evaluate(workflow));

        Assert.Equal("GHA009", finding.RuleId);
        Assert.Null(finding.LineNumber);
    }

    [Fact]
    public void Job_level_permissions_satisfy_the_declaration_requirement()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on: push",
            "jobs:",
            "  build:",
            "    permissions:",
            "      contents: read",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 15"
        ]));

        Assert.Empty(new UndeclaredPermissionsRule().Evaluate(workflow));
    }

    [Theory]
    [InlineData("permissions: {}")]
    [InlineData("permissions:")]
    public void An_empty_permissions_block_is_a_declaration_not_an_omission(
        string declaration)
    {
        // permissions: {} grants the job token nothing at all - the strongest
        // position a workflow can take. Counting entries cannot tell it apart
        // from saying nothing, and reporting it sent the reader to a
        // recommendation that would have WIDENED the grant to read-all.
        //
        // Found by pointing this project's rules at this project's own
        // workflows; the keep-warm job needs no token and says so.
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Keep warm",
            "on: push",
            declaration,
            "jobs:",
            "  ping:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 5"
        ]));

        Assert.Empty(new UndeclaredPermissionsRule().Evaluate(workflow));
    }

    [Fact]
    public void Id_token_write_is_not_reported_as_excessive()
    {
        // It grants no repository access - only the right to ask for an OIDC
        // token - and it is what removes a stored publish credential from a
        // deploy pipeline. Reporting it argued against the safer design, and
        // the offered fix (read-all) would have broken the deployment.
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Deploy",
            "on: push",
            "jobs:",
            "  deploy:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 15",
            "    permissions:",
            "      contents: read",
            "      id-token: write"
        ]));

        Assert.Empty(new ExcessivePermissionsRule().Evaluate(workflow));
    }

    [Fact]
    public void A_specific_write_grant_other_than_id_token_is_still_reported()
    {
        // The exemption is for id-token alone, not for named write grants
        // generally.
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Deploy",
            "on: push",
            "jobs:",
            "  deploy:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 15",
            "    permissions:",
            "      contents: write",
            "      id-token: write"
        ]));

        WorkflowFinding finding = Assert.Single(
            new ExcessivePermissionsRule().Evaluate(workflow));

        Assert.Equal("GHA002", finding.RuleId);
        Assert.Equal(8, finding.LineNumber);
    }

    [Fact]
    public void An_empty_permissions_block_grants_nothing_to_report_as_excessive()
    {
        // The companion check: saying nothing is not the same as granting
        // something, so GHA002 must stay quiet here too.
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Keep warm",
            "on: push",
            "permissions: {}",
            "jobs:",
            "  ping:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 5"
        ]));

        Assert.Empty(new ExcessivePermissionsRule().Evaluate(workflow));
    }

    [Theory]
    [InlineData("self-hosted")]
    [InlineData("[self-hosted, linux, x64]")]
    public void Self_hosted_runner_on_a_pull_request_trigger_is_reported(
        string runsOn)
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on: pull_request",
            "permissions:",
            "  contents: read",
            "jobs:",
            "  build:",
            $"    runs-on: {runsOn}",
            "    timeout-minutes: 15"
        ]));

        WorkflowFinding finding = Assert.Single(
            new SelfHostedRunnerRule().Evaluate(workflow));

        Assert.Equal("GHA010", finding.RuleId);
        Assert.Equal(7, finding.LineNumber);
    }

    [Fact]
    public void Self_hosted_runner_outside_a_pull_request_trigger_is_not_reported()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Deploy",
            "on:",
            "  workflow_dispatch:",
            "permissions:",
            "  contents: read",
            "jobs:",
            "  deploy:",
            "    runs-on: self-hosted",
            "    timeout-minutes: 15"
        ]));

        Assert.Empty(new SelfHostedRunnerRule().Evaluate(workflow));
    }

    [Fact]
    public void Artifact_download_in_a_workflow_run_job_is_reported()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Comment",
            "on:",
            "  workflow_run:",
            "    workflows: [CI]",
            "    types: [completed]",
            "permissions:",
            "  pull-requests: write",
            "jobs:",
            "  comment:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 15",
            "    steps:",
            "      - uses: actions/download-artifact@0000000000000000000000000000000000000000"
        ]));

        WorkflowFinding finding = Assert.Single(
            new ArtifactPoisoningRule().Evaluate(workflow));

        Assert.Equal("GHA011", finding.RuleId);
        Assert.Equal(13, finding.LineNumber);
    }

    [Fact]
    public void Artifact_download_under_an_ordinary_trigger_is_not_reported()
    {
        ParsedWorkflow workflow = Parse(string.Join('\n',
        [
            "name: Build",
            "on: push",
            "permissions:",
            "  contents: read",
            "jobs:",
            "  build:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 15",
            "    steps:",
            "      - uses: actions/download-artifact@0000000000000000000000000000000000000000"
        ]));

        Assert.Empty(new ArtifactPoisoningRule().Evaluate(workflow));
    }

    private ParsedWorkflow Parse(string content)
    {
        WorkflowParseResult result = _parser.Parse(
            new WorkflowDocument("workflow.yml", content));

        Assert.True(result.IsValid);
        return Assert.IsType<ParsedWorkflow>(result.Workflow);
    }
}
