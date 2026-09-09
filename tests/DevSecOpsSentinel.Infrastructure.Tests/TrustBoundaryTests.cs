using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;
using DevSecOpsSentinel.Infrastructure.Rules;

namespace DevSecOpsSentinel.Infrastructure.Tests;

/// <summary>
/// GHA004 and GHA006 establishing need before reporting, the same correction
/// GHA002 received.
///
/// Both rules named their own exception and then ignored it. GHA004 reported the
/// pull_request_target trigger as Critical whether or not any job executed
/// contributor code, so the documented-correct pattern - labelling a fork's pull
/// request - scored the same as a live execution path. GHA006's remediation said
/// "unless a later step needs to push with the job token" while nothing checked
/// whether one did, so a release job was told to remove the credential it pushes
/// with.
///
/// Suppression is the expensive direction for both, so every case that goes
/// quiet is paired with the neighbouring case that must not.
/// </summary>
public sealed class TrustBoundaryTests
{
    private readonly WorkflowParser _parser = new();

    // ---- GHA004: the trigger earns its severity ---------------------------

    [Fact]
    public void Evaluate_JobCheckingOutThePullRequestHead_StaysCritical()
    {
        ParsedWorkflow workflow = Parse(
            "name: Label",
            "on:",
            "  pull_request_target:",
            "jobs:",
            "  build:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 10",
            "    steps:",
            "      - uses: actions/checkout@v4",
            "        with:",
            "          ref: ${{ github.event.pull_request.head.sha }}");

        WorkflowFinding finding = Assert.Single(
            new UnsafePullRequestTargetRule().Evaluate(workflow));

        Assert.Equal(WorkflowSeverity.Critical, finding.Severity);

        // The two rules have to agree about the same workflow.
        Assert.Single(new UntrustedCheckoutRule().Evaluate(workflow));
    }

    [Fact]
    public void Evaluate_TriggerWithoutUntrustedCode_IsLowNotCritical()
    {
        // Labelling a fork's pull request is what the trigger is for. It needs a
        // reader's eye, not the band reserved for remote code execution.
        ParsedWorkflow workflow = Parse(
            "name: Label",
            "on:",
            "  pull_request_target:",
            "jobs:",
            "  label:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 10",
            "    permissions:",
            "      pull-requests: write",
            "    steps:",
            "      - uses: actions/labeler@v5");

        WorkflowFinding finding = Assert.Single(
            new UnsafePullRequestTargetRule().Evaluate(workflow));

        Assert.Equal(WorkflowSeverity.Low, finding.Severity);
        Assert.Contains("later edit", finding.Description);

        // Nothing untrusted is checked out, so GHA007 stays silent.
        Assert.Empty(new UntrustedCheckoutRule().Evaluate(workflow));
    }

    [Fact]
    public void Evaluate_CheckoutOfTheBaseBranch_IsNotTreatedAsUntrusted()
    {
        // A checkout with no ref takes the base, which is the trusted side.
        ParsedWorkflow workflow = Parse(
            "name: Comment",
            "on:",
            "  pull_request_target:",
            "jobs:",
            "  comment:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 10",
            "    steps:",
            "      - uses: actions/checkout@v4");

        Assert.Equal(
            WorkflowSeverity.Low,
            Assert.Single(new UnsafePullRequestTargetRule().Evaluate(workflow)).Severity);
    }

    [Fact]
    public void Evaluate_WorkflowWithoutThePrivilegedTrigger_IsNotReported()
    {
        ParsedWorkflow workflow = Parse(
            "name: Build",
            "on: pull_request",
            "jobs:",
            "  build:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 10",
            "    steps:",
            "      - uses: actions/checkout@v4",
            "        with:",
            "          ref: ${{ github.event.pull_request.head.sha }}");

        Assert.Empty(new UnsafePullRequestTargetRule().Evaluate(workflow));
    }

    // ---- GHA006: the token is left where something uses it ----------------

    [Fact]
    public void Evaluate_JobThatPushes_NeedsTheCredentialItPersisted()
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
            "        run: |",
            "          git tag v1.0.0",
            "          git push origin v1.0.0");

        Assert.Empty(new PersistedCredentialsRule().Evaluate(workflow));
    }

    [Fact]
    public void Evaluate_JobThatOnlyBuilds_IsStillReported()
    {
        // The neighbouring case: same shape, no push, so the credential sits on
        // disk for every later step with nothing needing it.
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
            "        run: |",
            "          dotnet build");

        WorkflowFinding finding = Assert.Single(
            new PersistedCredentialsRule().Evaluate(workflow));

        Assert.Equal(8, finding.LineNumber);
        Assert.Contains("Nothing in this job pushes", finding.Description);
    }

    [Fact]
    public void Evaluate_PushInAnotherJob_DoesNotExcuseThisOne()
    {
        // Credentials are per-job. The second job's push says nothing about the
        // first job's checkout.
        ParsedWorkflow workflow = Parse(
            "name: Two",
            "on: push",
            "jobs:",
            "  build:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 10",
            "    steps:",
            "      - uses: actions/checkout@v4",
            "      - name: Build",
            "        run: dotnet build",
            "  release:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 10",
            "    steps:",
            "      - uses: actions/checkout@v4",
            "      - name: Push",
            "        run: git push origin main");

        WorkflowFinding finding = Assert.Single(
            new PersistedCredentialsRule().Evaluate(workflow));

        Assert.Equal(8, finding.LineNumber);
    }

    [Fact]
    public void Evaluate_PushBeforeTheCheckout_DoesNotExcuseIt()
    {
        // Ordering matters: that push used whatever was on disk beforehand, not
        // the credential this checkout is about to write.
        ParsedWorkflow workflow = Parse(
            "name: Odd",
            "on: push",
            "jobs:",
            "  build:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 10",
            "    steps:",
            "      - name: Push",
            "        run: git push origin main",
            "      - uses: actions/checkout@v4");

        Assert.Single(new PersistedCredentialsRule().Evaluate(workflow));
    }

    [Fact]
    public void Evaluate_StepMerelyNamedAfterPushing_DoesNotExcuseIt()
    {
        // Only script text is searched. A step name that happens to read like a
        // command must not silence a real credential exposure.
        ParsedWorkflow workflow = Parse(
            "name: Build",
            "on: push",
            "jobs:",
            "  build:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 10",
            "    steps:",
            "      - uses: actions/checkout@v4",
            "      - name: Set up git push credentials",
            "        run: echo configured");

        Assert.Single(new PersistedCredentialsRule().Evaluate(workflow));
    }

    [Fact]
    public void Evaluate_OptionBetweenGitAndPush_IsStillRecognisedAsAPush()
    {
        ParsedWorkflow workflow = Parse(
            "name: Pages",
            "on: push",
            "jobs:",
            "  publish:",
            "    runs-on: ubuntu-latest",
            "    timeout-minutes: 10",
            "    steps:",
            "      - uses: actions/checkout@v4",
            "      - name: Publish",
            "        run: git -C site push origin gh-pages");

        Assert.Empty(new PersistedCredentialsRule().Evaluate(workflow));
    }

    [Fact]
    public void Evaluate_PersistCredentialsDisabled_ClosesTheFinding()
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
            "        with:",
            "          persist-credentials: false",
            "      - name: Build",
            "        run: dotnet build");

        Assert.Empty(new PersistedCredentialsRule().Evaluate(workflow));
    }

    private ParsedWorkflow Parse(params string[] lines)
    {
        WorkflowParseResult result = _parser.Parse(
            new WorkflowDocument("workflow.yml", string.Join('\n', lines)));

        Assert.True(result.IsValid, string.Join("; ", result.Errors));
        return Assert.IsType<ParsedWorkflow>(result.Workflow);
    }
}
