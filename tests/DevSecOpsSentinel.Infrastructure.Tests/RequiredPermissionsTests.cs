using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;
using DevSecOpsSentinel.Infrastructure.Rules;

namespace DevSecOpsSentinel.Infrastructure.Tests;

/// <summary>
/// GHA002 deciding whether a write grant is needed before calling it excessive.
///
/// The rule used to report every write, which made the correct configuration
/// indistinguishable from the dangerous one: a CodeQL job holding the single
/// scope it cannot upload results without scored the same High as a job that
/// could push to the default branch. Three grants in this repository's own
/// workflows carried hand-written exemptions because of it.
///
/// What is asserted here is the boundary, in both directions - a required scope
/// is not reported, and an unrequired one still is. A table that quietly grew
/// too permissive would suppress real findings, which is the more expensive
/// failure, so every exemption below is paired with its negative case.
/// </summary>
public sealed class RequiredPermissionsTests
{
    private readonly WorkflowParser _parser = new();

    [Fact]
    public void Codeql_job_holding_only_what_it_needs_is_not_reported()
    {
        ParsedWorkflow workflow = Parse(
            "name: CodeQL",
            "on: push",
            "permissions:",
            "  contents: read",
            "jobs:",
            "  analyze:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 20",
            "    permissions:",
            "      contents: read",
            "      security-events: write",
            "    steps:",
            "      - uses: github/codeql-action/init@v3",
            "      - uses: github/codeql-action/analyze@v3");

        Assert.Empty(new ExcessivePermissionsRule().Evaluate(workflow));
    }

    [Fact]
    public void The_same_grant_without_the_action_is_still_reported()
    {
        // The negative of the case above: nothing in the job uploads results, so
        // the scope has no justification and the exemption must not apply.
        ParsedWorkflow workflow = Parse(
            "name: Build",
            "on: push",
            "jobs:",
            "  build:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 20",
            "    permissions:",
            "      security-events: write",
            "    steps:",
            "      - uses: actions/checkout@v4");

        WorkflowFinding finding = Assert.Single(
            new ExcessivePermissionsRule().Evaluate(workflow));

        Assert.Equal(8, finding.LineNumber);
        Assert.Contains("Nothing in this job", finding.Description);
    }

    [Fact]
    public void A_required_scope_excuses_only_itself()
    {
        // CodeQL justifies security-events and nothing else; contents: write in
        // the same job is still an excess and still High.
        ParsedWorkflow workflow = Parse(
            "name: CodeQL",
            "on: push",
            "jobs:",
            "  analyze:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 20",
            "    permissions:",
            "      security-events: write",
            "      contents: write",
            "    steps:",
            "      - uses: github/codeql-action/analyze@v3");

        WorkflowFinding finding = Assert.Single(
            new ExcessivePermissionsRule().Evaluate(workflow));

        Assert.Equal(9, finding.LineNumber);
        Assert.Equal(WorkflowSeverity.High, finding.Severity);
    }

    [Fact]
    public void A_sub_action_matches_the_repository_entry()
    {
        // One catalogue entry covers init, analyze and upload-sarif.
        ParsedWorkflow workflow = Parse(
            "name: Upload",
            "on: push",
            "jobs:",
            "  upload:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 20",
            "    permissions:",
            "      security-events: write",
            "    steps:",
            "      - uses: github/codeql-action/upload-sarif@v3");

        Assert.Empty(new ExcessivePermissionsRule().Evaluate(workflow));
    }

    [Fact]
    public void A_sha_pinned_action_matches_the_same_entry()
    {
        // Pinning is the recommended form, so it must not cost the exemption.
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
            "      - uses: github/codeql-action/analyze@18420e3271f74589575af831a523c833acda327f");

        Assert.Empty(new ExcessivePermissionsRule().Evaluate(workflow));
    }

    [Fact]
    public void A_lookalike_repository_does_not_borrow_the_exemption()
    {
        // Prefix matching stops at the separator: codeql-action-mirror is not
        // codeql-action, and an attacker choosing the name must not inherit it.
        ParsedWorkflow workflow = Parse(
            "name: Fake",
            "on: push",
            "jobs:",
            "  analyze:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 20",
            "    permissions:",
            "      security-events: write",
            "    steps:",
            "      - uses: github/codeql-action-mirror/analyze@v3");

        Assert.Single(new ExcessivePermissionsRule().Evaluate(workflow));
    }

    [Theory]
    [InlineData("always")]
    [InlineData("on-failure")]
    public void Dependency_review_needs_pull_requests_when_it_comments(string mode)
    {
        ParsedWorkflow workflow = Parse(
            "name: Review",
            "on: pull_request",
            "jobs:",
            "  review:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 10",
            "    permissions:",
            "      contents: read",
            "      pull-requests: write",
            "    steps:",
            "      - uses: actions/dependency-review-action@v4",
            "        with:",
            $"          comment-summary-in-pr: {mode}");

        Assert.Empty(new ExcessivePermissionsRule().Evaluate(workflow));
    }

    [Theory]
    [InlineData("never")]
    [InlineData(null)]
    public void Dependency_review_does_not_need_it_when_it_stays_quiet(string? mode)
    {
        // A conditional requirement must not excuse the configurations where the
        // condition does not hold, or the entry becomes a blanket exemption.
        string[] step = mode is null
            ? ["      - uses: actions/dependency-review-action@v4"]
            :
            [
                "      - uses: actions/dependency-review-action@v4",
                "        with:",
                $"          comment-summary-in-pr: {mode}"
            ];

        ParsedWorkflow workflow = Parse(
        [
            "name: Review",
            "on: pull_request",
            "jobs:",
            "  review:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 10",
            "    permissions:",
            "      contents: read",
            "      pull-requests: write",
            "    steps:",
            .. step
        ]);

        Assert.Single(new ExcessivePermissionsRule().Evaluate(workflow));
    }

    [Fact]
    public void A_required_scope_granted_to_every_job_is_reported_as_too_broad()
    {
        // Workflow scope reaches jobs that have no use for it, including ones
        // added later, so the advice is to move it rather than remove it.
        ParsedWorkflow workflow = Parse(
            "name: CodeQL",
            "on: push",
            "permissions:",
            "  security-events: write",
            "jobs:",
            "  analyze:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 20",
            "    steps:",
            "      - uses: github/codeql-action/analyze@v3");

        WorkflowFinding finding = Assert.Single(
            new ExcessivePermissionsRule().Evaluate(workflow));

        Assert.Equal(4, finding.LineNumber);
        Assert.Equal(WorkflowSeverity.Low, finding.Severity);
        Assert.Contains("Move", finding.Recommendation);
    }

    [Theory]
    [InlineData("contents", WorkflowSeverity.High)]
    [InlineData("packages", WorkflowSeverity.High)]
    [InlineData("actions", WorkflowSeverity.High)]
    [InlineData("pull-requests", WorkflowSeverity.Medium)]
    [InlineData("issues", WorkflowSeverity.Medium)]
    [InlineData("security-events", WorkflowSeverity.Low)]
    [InlineData("checks", WorkflowSeverity.Low)]
    [InlineData("statuses", WorkflowSeverity.Low)]
    public void Severity_follows_what_the_scope_can_do(string scope, WorkflowSeverity expected)
    {
        // Pushing code and hiding an alert are not the same risk, and a constant
        // severity across every scope hides that.
        ParsedWorkflow workflow = Parse(
            "name: Build",
            "on: push",
            "jobs:",
            "  build:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 10",
            "    permissions:",
            $"      {scope}: write",
            "    steps:",
            "      - uses: actions/checkout@v4");

        WorkflowFinding finding = Assert.Single(
            new ExcessivePermissionsRule().Evaluate(workflow));

        Assert.Equal(expected, finding.Severity);
    }

    [Fact]
    public void An_unknown_scope_is_reported_rather_than_dismissed()
    {
        // A scope GitHub adds after this table was written must not fall through
        // the exemption path unreported.
        ParsedWorkflow workflow = Parse(
            "name: Build",
            "on: push",
            "jobs:",
            "  build:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 10",
            "    permissions:",
            "      some-future-scope: write",
            "    steps:",
            "      - uses: actions/checkout@v4");

        WorkflowFinding finding = Assert.Single(
            new ExcessivePermissionsRule().Evaluate(workflow));

        Assert.Equal(WorkflowSeverity.Medium, finding.Severity);
    }

    [Fact]
    public void Write_all_is_reported_whatever_the_job_runs()
    {
        // No action requires every scope at once, so nothing exempts write-all.
        ParsedWorkflow workflow = Parse(
            "name: CodeQL",
            "on: push",
            "permissions: write-all",
            "jobs:",
            "  analyze:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 20",
            "    steps:",
            "      - uses: github/codeql-action/analyze@v3");

        WorkflowFinding finding = Assert.Single(
            new ExcessivePermissionsRule().Evaluate(workflow));

        Assert.Equal(WorkflowSeverity.High, finding.Severity);
        Assert.True(finding.IsAutomaticallyFixable);
    }

    [Fact]
    public void A_reusable_workflow_call_cannot_justify_a_grant()
    {
        // The called workflow's steps are not visible here, so its needs are not
        // knowable; the conservative answer is to report and let a human say.
        ParsedWorkflow workflow = Parse(
            "name: Caller",
            "on: push",
            "jobs:",
            "  call:",
            "    permissions:",
            "      security-events: write",
            "    uses: ./.github/workflows/scan.yml");

        Assert.Single(new ExcessivePermissionsRule().Evaluate(workflow));
    }

    private ParsedWorkflow Parse(params string[] lines) => Parse((IEnumerable<string>)lines);

    private ParsedWorkflow Parse(IEnumerable<string> lines)
    {
        WorkflowParseResult result = _parser.Parse(
            new WorkflowDocument("workflow.yml", string.Join('\n', lines)));

        Assert.True(result.IsValid, string.Join("; ", result.Errors));
        return Assert.IsType<ParsedWorkflow>(result.Workflow);
    }
}
