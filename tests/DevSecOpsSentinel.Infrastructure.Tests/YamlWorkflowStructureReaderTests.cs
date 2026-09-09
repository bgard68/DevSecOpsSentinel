using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Tests;

/// <summary>
/// Unit tests for the reader that turns workflow YAML into the structure the
/// rules query. It is the only component that decides what a job, a step, a
/// permission grant and a trigger <em>are</em>, so a silent drop here is a rule
/// that reports nothing on a workflow that is genuinely unsafe.
///
/// Line numbers are asserted as exact values throughout. They are what an
/// operator uses to find the finding in the file, and an off-by-one is
/// invisible to any assertion that only checks a count.
/// </summary>
public sealed class YamlWorkflowStructureReaderTests
{
    private static WorkflowStructure Read(string content)
    {
        bool succeeded = YamlWorkflowStructureReader.TryRead(
            content,
            out WorkflowStructure structure,
            out string? error);

        Assert.True(succeeded, $"Expected YAML to parse. Reader reported: {error}");
        Assert.Null(error);

        return structure;
    }

    private const string CompleteWorkflow =
        "name: Build\n" +          // 1
        "on:\n" +                  // 2
        "  push:\n" +              // 3
        "  pull_request:\n" +      // 4
        "permissions:\n" +         // 5
        "  contents: read\n" +     // 6
        "  issues: write\n" +      // 7
        "jobs:\n" +                // 8
        "  build:\n" +             // 9
        "    runs-on: ubuntu-latest\n" +   // 10
        "    timeout-minutes: 15\n" +      // 11
        "    permissions: {}\n" +          // 12
        "    steps:\n" +                   // 13
        "      - uses: actions/checkout@v4\n" + // 14
        "        with:\n" +                     // 15
        "          ref: main\n";                // 16

    // ------------------------------------------------------- The happy path

    [Fact]
    public void TryRead_CompleteWorkflow_ReportsEveryElementAtItsOwnSourceLine()
    {
        // Arrange & Act
        WorkflowStructure structure = Read(CompleteWorkflow);

        // Assert
        Assert.Equal(["push", "pull_request"], structure.Triggers);
        Assert.True(structure.PermissionsDeclared);

        Assert.Equal(
            [
                new WorkflowPermissionEntry("contents", "read", 6),
                new WorkflowPermissionEntry("issues", "write", 7)
            ],
            structure.Permissions);

        WorkflowStructuredJob job = Assert.Single(structure.Jobs);

        Assert.Equal("build", job.Name);
        Assert.Equal(9, job.Line);
        Assert.Equal("ubuntu-latest", job.RunsOn);
        Assert.Equal(10, job.RunsOnLine);
        Assert.Equal(11, job.TimeoutLine);
        Assert.Null(job.Uses);
        Assert.Null(job.Secrets);
        Assert.Null(job.SecretsLine);

        WorkflowStructuredStep step = Assert.Single(job.Steps);

        Assert.Equal("actions/checkout@v4", step.Uses);
        Assert.Equal(14, step.Line);
        Assert.Equal(14, step.UsesLine);
        Assert.Equal(new WorkflowInputValue("main", 16), step.Input("ref"));
    }

    [Fact]
    public void TryRead_JobDeclaresAnEmptyPermissionsMap_SetsTheFlagWithoutAnyEntries()
    {
        // Arrange & Act. `permissions: {}` in CompleteWorkflow is the case that
        // separates "declared and empty" from "never declared". Only the flag
        // can tell them apart; the entry list is empty for both.
        WorkflowStructuredJob job = Assert.Single(Read(CompleteWorkflow).Jobs);

        // Assert
        Assert.True(job.PermissionsDeclared);
        Assert.Empty(job.Permissions);
        Assert.False(Read(CompleteWorkflow).DeclaresNoPermissions);
    }

    // ------------------------------------------------------------- Triggers

    [Fact]
    public void TryRead_TriggersWrittenAsAFlowSequence_ReadsEachEntry()
    {
        // Arrange
        string content = "on: [push, pull_request]\njobs: {}\n";

        // Act
        WorkflowStructure structure = Read(content);

        // Assert
        Assert.Equal(["push", "pull_request"], structure.Triggers);
    }

    [Fact]
    public void TryRead_TriggerWrittenAsABareScalar_ReadsTheSingleTrigger()
    {
        // Arrange
        string content = "on: push\njobs: {}\n";

        // Act
        WorkflowStructure structure = Read(content);

        // Assert
        Assert.Equal(["push"], structure.Triggers);
    }

    [Fact]
    public void TryRead_OnKeyEmittedAsTheYaml11BooleanTrue_StillReadsTheTriggers()
    {
        // Arrange. YAML 1.1 resolves an unquoted `on` to the boolean true, so a
        // workflow round-tripped through such an emitter arrives with the key
        // spelled `true`. Reading only `on` would report a workflow with no
        // triggers at all, and every trigger-conditional rule would go quiet.
        string content = "true:\n  push:\njobs: {}\n";

        // Act
        WorkflowStructure structure = Read(content);

        // Assert
        Assert.Equal(["push"], structure.Triggers);
    }

    [Fact]
    public void TryRead_TriggerScalarIsAnEmptyString_ReportsNoTriggers()
    {
        // Arrange
        string content = "on: ''\njobs: {}\n";

        // Act
        WorkflowStructure structure = Read(content);

        // Assert
        Assert.Empty(structure.Triggers);
    }

    // ---------------------------------------------------------- Permissions

    [Fact]
    public void TryRead_PermissionsWrittenAsAScalar_ReportsOneUnnamedGrant()
    {
        // Arrange. `permissions: write-all` has no key of its own, so the name
        // is empty and the value carries the grant.
        string content = "on: push\npermissions: write-all\njobs: {}\n";

        // Act
        WorkflowStructure structure = Read(content);

        // Assert
        Assert.Equal(
            [new WorkflowPermissionEntry(string.Empty, "write-all", 2)],
            structure.Permissions);
        Assert.True(structure.PermissionsDeclared);
    }

    [Fact]
    public void TryRead_PermissionEntryHasASequenceValue_DropsItAndKeepsScalarSiblings()
    {
        // Arrange. A grant whose value is a sequence is not a grant GitHub
        // accepts. It is skipped, but its presence must not discard the valid
        // entry beside it.
        string content =
            "on: push\n" +
            "permissions:\n" +
            "  contents:\n" +
            "    - read\n" +
            "  issues: write\n";

        // Act
        WorkflowStructure structure = Read(content);

        // Assert
        Assert.Equal(
            [new WorkflowPermissionEntry("issues", "write", 5)],
            structure.Permissions);
        Assert.True(structure.PermissionsDeclared);
    }

    [Fact]
    public void TryRead_NoPermissionsKeyAnywhere_LeavesTheStructureDeclaringNone()
    {
        // Arrange
        string content = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n";

        // Act
        WorkflowStructure structure = Read(content);

        // Assert
        Assert.False(structure.PermissionsDeclared);
        Assert.True(structure.DeclaresNoPermissions);
        Assert.Empty(structure.AllPermissions);
    }

    // ----------------------------------------------------------------- Jobs

    [Fact]
    public void TryRead_RunsOnWrittenAsALabelSequence_FlattensToACommaJoinedValue()
    {
        // Arrange. The self-hosted runner rule matches against the whole label
        // list, so a sequence has to become one comparable string.
        string content = "on: push\njobs:\n  a:\n    runs-on: [self-hosted, linux]\n";

        // Act
        WorkflowStructuredJob job = Assert.Single(Read(content).Jobs);

        // Assert
        Assert.Equal("self-hosted,linux", job.RunsOn);
        Assert.Equal(4, job.RunsOnLine);
    }

    [Fact]
    public void TryRead_ReusableWorkflowJob_CapturesUsesAndTheInheritedSecrets()
    {
        // Arrange
        string content =
            "on: push\n" +
            "jobs:\n" +
            "  call:\n" +
            "    uses: org/repo/.github/workflows/release.yml@v1\n" +
            "    secrets: inherit\n";

        // Act
        WorkflowStructuredJob job = Assert.Single(Read(content).Jobs);

        // Assert
        Assert.Equal("org/repo/.github/workflows/release.yml@v1", job.Uses);
        Assert.Equal("inherit", job.Secrets);
        Assert.Equal(5, job.SecretsLine);
        Assert.Null(job.RunsOn);
        Assert.Null(job.RunsOnLine);
        Assert.Empty(job.Steps);
    }

    [Fact]
    public void TryRead_JobValueIsAScalarRatherThanAMapping_DropsItAndKeepsTheRest()
    {
        // Arrange
        string content =
            "on: push\n" +
            "jobs:\n" +
            "  a: some-scalar\n" +
            "  b:\n" +
            "    runs-on: ubuntu-latest\n";

        // Act
        WorkflowStructure structure = Read(content);

        // Assert
        WorkflowStructuredJob job = Assert.Single(structure.Jobs);
        Assert.Equal("b", job.Name);
        Assert.Equal(4, job.Line);
    }

    [Fact]
    public void TryRead_JobsWrittenInFlowStyle_ReadsThemFromTheSingleSourceLine()
    {
        // Arrange
        string content = "on: push\njobs: {a: {runs-on: ubuntu-latest}}\n";

        // Act
        WorkflowStructuredJob job = Assert.Single(Read(content).Jobs);

        // Assert
        Assert.Equal("a", job.Name);
        Assert.Equal(2, job.Line);
        Assert.Equal("ubuntu-latest", job.RunsOn);
        Assert.Equal(2, job.RunsOnLine);
    }

    [Fact]
    public void TryRead_AliasJobReferencingAnAnchor_ResolvesToTheAnchoredContent()
    {
        // Arrange. An alias job is a real job GitHub will run. Reporting one job
        // here would leave the second one unexamined by every rule. Its element
        // lines point at the anchor, which is where the content is written.
        string content =
            "on: push\n" +
            "jobs:\n" +
            "  a: &base\n" +
            "    runs-on: ubuntu-latest\n" +
            "    timeout-minutes: 5\n" +
            "  b: *base\n";

        // Act
        WorkflowStructure structure = Read(content);

        // Assert
        Assert.Equal(["a", "b"], structure.Jobs.Select(job => job.Name));
        Assert.Equal([3, 6], structure.Jobs.Select(job => job.Line));
        Assert.Equal(["ubuntu-latest", "ubuntu-latest"], structure.Jobs.Select(job => job.RunsOn));
        Assert.Equal([5, 5], structure.Jobs.Select(job => job.TimeoutLine));
    }

    [Fact]
    public void TryRead_TopLevelKeysWrittenInUpperCase_ResolvesThemCaseInsensitively()
    {
        // Arrange
        string content =
            "ON: push\n" +
            "PERMISSIONS: read-all\n" +
            "JOBS:\n" +
            "  a:\n" +
            "    RUNS-ON: ubuntu-latest\n";

        // Act
        WorkflowStructure structure = Read(content);

        // Assert
        Assert.Equal(["push"], structure.Triggers);
        Assert.Equal(
            [new WorkflowPermissionEntry(string.Empty, "read-all", 2)],
            structure.Permissions);
        Assert.Equal("ubuntu-latest", Assert.Single(structure.Jobs).RunsOn);
    }

    // ---------------------------------------------------------------- Steps

    [Fact]
    public void TryRead_StepsValueIsNotASequence_ReportsNoStepsAndKeepsTheJob()
    {
        // Arrange
        string content = "on: push\njobs:\n  a:\n    steps: nope\n";

        // Act
        WorkflowStructuredJob job = Assert.Single(Read(content).Jobs);

        // Assert
        Assert.Equal("a", job.Name);
        Assert.Empty(job.Steps);
    }

    [Fact]
    public void TryRead_SequenceMixesScalarAndMappingSteps_KeepsOnlyTheMappingStep()
    {
        // Arrange
        string content =
            "on: push\n" +
            "jobs:\n" +
            "  a:\n" +
            "    steps:\n" +
            "      - just-a-string\n" +
            "      - uses: x/y@v1\n";

        // Act
        WorkflowStructuredStep step = Assert.Single(Assert.Single(Read(content).Jobs).Steps);

        // Assert
        Assert.Equal("x/y@v1", step.Uses);
        Assert.Equal(6, step.Line);
        Assert.Equal(6, step.UsesLine);
    }

    [Fact]
    public void TryRead_StepRunsAScriptWithNoUses_KeepsTheStepWithANullReference()
    {
        // Arrange
        string content =
            "on: push\n" +
            "jobs:\n" +
            "  a:\n" +
            "    steps:\n" +
            "      - run: echo hi\n";

        // Act
        WorkflowStructuredStep step = Assert.Single(Assert.Single(Read(content).Jobs).Steps);

        // Assert
        Assert.Null(step.Uses);
        Assert.Null(step.UsesLine);
        Assert.Equal(5, step.Line);
        Assert.Empty(step.With);
    }

    [Fact]
    public void TryRead_StepInputHasANestedMappingValue_DropsItAndKeepsScalarSiblings()
    {
        // Arrange. A non-scalar input cannot be pattern-matched by the rules, so
        // it is skipped. The scalar beside it must survive, or a rule reading
        // `with` on a step that has one nested input goes blind to all of them.
        string content =
            "on: push\n" +
            "jobs:\n" +
            "  a:\n" +
            "    steps:\n" +
            "      - uses: x/y@v1\n" +
            "        with:\n" +
            "          nested:\n" +
            "            k: v\n" +
            "          flat: ok\n";

        // Act
        WorkflowStructuredStep step = Assert.Single(Assert.Single(Read(content).Jobs).Steps);

        // Assert
        Assert.Equal(new WorkflowInputValue("ok", 9), Assert.Single(step.With).Value);
        Assert.Null(step.Input("nested"));
    }

    [Fact]
    public void TryRead_StepInputNameIsUpperCase_IsRetrievableByItsLowerCaseName()
    {
        // Arrange
        string content =
            "on: push\n" +
            "jobs:\n" +
            "  a:\n" +
            "    steps:\n" +
            "      - uses: actions/github-script@v7\n" +
            "        with:\n" +
            "          SCRIPT: console.log(1)\n";

        // Act
        WorkflowStructuredStep step = Assert.Single(Assert.Single(Read(content).Jobs).Steps);

        // Assert
        Assert.Equal(new WorkflowInputValue("console.log(1)", 7), step.Input("script"));
    }

    // ------------------------------------------------- Degenerate documents

    [Fact]
    public void TryRead_MalformedYaml_ReportsFailureAndLeavesTheStructureEmpty()
    {
        // Arrange
        string content = "on: push\n  bad: [unclosed\n";

        // Act
        bool succeeded = YamlWorkflowStructureReader.TryRead(
            content,
            out WorkflowStructure structure,
            out string? error);

        // Assert. The message wording belongs to YamlDotNet, so the contract
        // asserted here is that a caller is told it failed and is handed the
        // empty structure rather than a partly-populated one.
        Assert.False(succeeded);
        Assert.False(string.IsNullOrWhiteSpace(error));
        Assert.Same(WorkflowStructure.Empty, structure);
    }

    [Fact]
    public void TryRead_EmptyContent_SucceedsWithTheEmptyStructure()
    {
        // Arrange & Act
        bool succeeded = YamlWorkflowStructureReader.TryRead(
            string.Empty,
            out WorkflowStructure structure,
            out string? error);

        // Assert. An empty file is not a parse failure; it is a workflow with
        // nothing in it, and it must not be reported as malformed YAML.
        Assert.True(succeeded);
        Assert.Null(error);
        Assert.Same(WorkflowStructure.Empty, structure);
    }

    [Fact]
    public void TryRead_RootNodeIsAScalarNotAMapping_SucceedsWithTheEmptyStructure()
    {
        // Arrange & Act
        bool succeeded = YamlWorkflowStructureReader.TryRead(
            "just-a-string\n",
            out WorkflowStructure structure,
            out string? error);

        // Assert
        Assert.True(succeeded);
        Assert.Null(error);
        Assert.Same(WorkflowStructure.Empty, structure);
    }

    [Fact]
    public void TryRead_StreamHoldsSeveralDocuments_ReadsOnlyTheFirst()
    {
        // Arrange. GitHub runs the first document in the file. Merging a later
        // one would report triggers on a workflow that does not have them.
        string content =
            "on: push\n" +
            "jobs: {}\n" +
            "---\n" +
            "on: schedule\n";

        // Act
        WorkflowStructure structure = Read(content);

        // Assert
        Assert.Equal(["push"], structure.Triggers);
    }
}
