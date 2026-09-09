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
    public void Evaluate_CodeqlJobHoldingOnlyTheScopeItNeeds_IsNotReported()
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
    public void Evaluate_SameGrantWithoutTheActionThatNeedsIt_IsStillReported()
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
    public void Evaluate_RequiredScopeBesideAnUnrequiredOne_ExcusesOnlyItself()
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
    public void Evaluate_SubActionOfAKnownRepository_MatchesTheRepositoryEntry()
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
    public void Evaluate_ShaPinnedAction_MatchesTheSameRepositoryEntry()
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
    public void Evaluate_LookalikeRepositoryName_DoesNotBorrowTheExemption()
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
    public void Evaluate_DependencyReviewThatComments_NeedsPullRequestsWrite(string mode)
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
    public void Evaluate_DependencyReviewThatStaysQuiet_DoesNotNeedPullRequestsWrite(string? mode)
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
    public void Evaluate_RequiredScopeGrantedToEveryJob_IsReportedAsTooBroad()
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
    public void Evaluate_DifferentWriteScopes_AssignsSeverityByWhatTheScopeCanDo(string scope, WorkflowSeverity expected)
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
    public void Evaluate_UnknownScope_IsReportedRatherThanDismissed()
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
    public void Evaluate_WriteAll_IsReportedWhateverTheJobRuns()
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
    public void Evaluate_ReusableWorkflowCall_CannotJustifyAGrant()
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
