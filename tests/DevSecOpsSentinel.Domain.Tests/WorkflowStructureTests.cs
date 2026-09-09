using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Domain.Tests;

/// <summary>
/// Unit tests for the structural model the rules query. Every member here is a
/// pure projection over data already in memory, so these run with no parser, no
/// I/O and no test double.
///
/// The distinctions being pinned are the ones the rule engine acts on and that a
/// reader cannot recover from a count: an absent <c>permissions</c> key versus an
/// empty one, a substring trigger match versus an exact one, and an action
/// reference that merely shares a prefix with the action being looked for.
/// </summary>
public sealed class WorkflowStructureTests
{
    private static WorkflowStructuredStep Step(
        string? uses,
        int line = 1,
        IReadOnlyDictionary<string, WorkflowInputValue>? with = null) =>
        new(
            uses,
            line,
            uses is null ? null : line,
            with ?? new Dictionary<string, WorkflowInputValue>(
                StringComparer.OrdinalIgnoreCase));

    private static WorkflowStructuredJob Job(
        string name,
        int line = 1,
        IReadOnlyList<WorkflowPermissionEntry>? permissions = null,
        IReadOnlyList<WorkflowStructuredStep>? steps = null,
        bool permissionsDeclared = false) =>
        new(name, line, null, permissions ?? [], steps ?? [])
        {
            PermissionsDeclared = permissionsDeclared
        };

    // ------------------------------------------------------------------ Empty

    [Fact]
    public void Empty_NoArguments_ExposesNoTriggersPermissionsOrJobs()
    {
        // Arrange & Act
        WorkflowStructure structure = WorkflowStructure.Empty;

        // Assert
        Assert.Empty(structure.Triggers);
        Assert.Empty(structure.Permissions);
        Assert.Empty(structure.Jobs);
        Assert.False(structure.PermissionsDeclared);
        Assert.True(structure.DeclaresNoPermissions);
    }

    [Fact]
    public void Empty_AccessedTwice_ReturnsTheSameSharedInstance()
    {
        // Arrange & Act
        WorkflowStructure first = WorkflowStructure.Empty;
        WorkflowStructure second = WorkflowStructure.Empty;

        // Assert
        Assert.Same(first, second);
    }

    // --------------------------------------------------- DeclaresNoPermissions

    [Fact]
    public void DeclaresNoPermissions_NeitherWorkflowNorJobDeclaresTheKey_ReturnsTrue()
    {
        // Arrange
        WorkflowStructure structure = new(["push"], [], [Job("build")])
        {
            PermissionsDeclared = false
        };

        // Act
        bool declaresNone = structure.DeclaresNoPermissions;

        // Assert
        Assert.True(declaresNone);
    }

    [Fact]
    public void DeclaresNoPermissions_WorkflowDeclaresAnEmptyPermissionsMap_ReturnsFalse()
    {
        // Arrange. A `permissions: {}` key is the most restrictive grant GitHub
        // accepts. Counting entries reports zero for both this and an absent
        // key, and advising the author to add permissions here would widen a
        // grant that is already empty.
        WorkflowStructure structure = new(["push"], [], [Job("build")])
        {
            PermissionsDeclared = true
        };

        // Act
        bool declaresNone = structure.DeclaresNoPermissions;

        // Assert
        Assert.False(declaresNone);
        Assert.Empty(structure.Permissions);
    }

    [Fact]
    public void DeclaresNoPermissions_OnlyOneOfTwoJobsDeclaresTheKey_ReturnsFalse()
    {
        // Arrange
        WorkflowStructure structure = new(
            ["push"],
            [],
            [Job("build"), Job("publish", permissionsDeclared: true)])
        {
            PermissionsDeclared = false
        };

        // Act
        bool declaresNone = structure.DeclaresNoPermissions;

        // Assert
        Assert.False(declaresNone);
    }

    [Fact]
    public void DeclaresNoPermissions_WorkflowHasNoJobsAndNoPermissionsKey_ReturnsTrue()
    {
        // Arrange. All() over an empty job list is true, so the workflow-level
        // flag is the only thing standing between this and a false negative.
        WorkflowStructure structure = new(["push"], [], [])
        {
            PermissionsDeclared = false
        };

        // Act
        bool declaresNone = structure.DeclaresNoPermissions;

        // Assert
        Assert.True(declaresNone);
    }

    // -------------------------------------------------------- AllPermissions

    [Fact]
    public void AllPermissions_WorkflowAndJobGrantsPresent_ReturnsWorkflowGrantsThenJobOrder()
    {
        // Arrange
        WorkflowPermissionEntry workflowGrant = new("contents", "read", 3);
        WorkflowPermissionEntry firstJobGrant = new("issues", "write", 9);
        WorkflowPermissionEntry secondJobGrant = new("packages", "write", 15);

        WorkflowStructure structure = new(
            ["push"],
            [workflowGrant],
            [
                Job("build", permissions: [firstJobGrant], permissionsDeclared: true),
                Job("publish", permissions: [secondJobGrant], permissionsDeclared: true)
            ]);

        // Act
        WorkflowPermissionEntry[] all = structure.AllPermissions.ToArray();

        // Assert
        Assert.Equal([workflowGrant, firstJobGrant, secondJobGrant], all);
    }

    [Fact]
    public void AllPermissions_NoGrantsAnywhere_ReturnsAnEmptySequence()
    {
        // Arrange
        WorkflowStructure structure = new(
            ["push"],
            [],
            [Job("build"), Job("publish")]);

        // Act
        WorkflowPermissionEntry[] all = structure.AllPermissions.ToArray();

        // Assert
        Assert.Empty(all);
    }

    // --------------------------------------------------------------- AllSteps

    [Fact]
    public void AllSteps_MultipleJobsWithSteps_FlattensInJobThenStepOrder()
    {
        // Arrange
        WorkflowStructuredStep checkout = Step("actions/checkout@v4", 10);
        WorkflowStructuredStep setup = Step("actions/setup-node@v4", 12);
        WorkflowStructuredStep publish = Step("actions/upload-artifact@v4", 20);

        WorkflowStructure structure = new(
            ["push"],
            [],
            [
                Job("build", steps: [checkout, setup]),
                Job("release", steps: [publish])
            ]);

        // Act
        WorkflowStructuredStep[] steps = structure.AllSteps.ToArray();

        // Assert
        Assert.Equal([checkout, setup, publish], steps);
    }

    [Fact]
    public void AllSteps_JobDeclaresNoSteps_ContributesNothingRatherThanANullEntry()
    {
        // Arrange. A reusable-workflow job carries `uses` and no `steps` at all.
        WorkflowStructuredStep only = Step("actions/checkout@v4", 8);

        WorkflowStructure structure = new(
            ["push"],
            [],
            [Job("call"), Job("build", steps: [only])]);

        // Act
        WorkflowStructuredStep[] steps = structure.AllSteps.ToArray();

        // Assert
        Assert.Equal([only], steps);
    }

    // ------------------------------------------------------------- HasTrigger

    [Theory]
    [InlineData("push", true)]
    [InlineData("PUSH", true)]
    [InlineData("PuSh", true)]
    [InlineData("schedule", false)]
    [InlineData("", true)]
    public void HasTrigger_TriggerListContainsPush_MatchesCaseInsensitively(
        string probe,
        bool expected)
    {
        // Arrange. The empty probe is included deliberately: Contains("") holds
        // for every string, so a rule that passes an unset option matches
        // everything rather than failing closed.
        WorkflowStructure structure = new(["push", "workflow_dispatch"], [], []);

        // Act
        bool matched = structure.HasTrigger(probe);

        // Assert
        Assert.Equal(expected, matched);
    }

    [Fact]
    public void HasTrigger_TriggerIsPullRequestTarget_AlsoMatchesTheShorterProbe()
    {
        // Arrange. HasTrigger is a substring test, so the privileged
        // `pull_request_target` trigger also answers to `pull_request`. A rule
        // that means the safe trigger and asks for the prefix gets both. Pinned
        // here so the ambiguity stays a decision rather than a surprise.
        WorkflowStructure structure = new(["pull_request_target"], [], []);

        // Act
        bool matchedPrefix = structure.HasTrigger("pull_request");
        bool matchedExact = structure.HasTrigger("pull_request_target");

        // Assert
        Assert.True(matchedPrefix);
        Assert.True(matchedExact);
    }

    [Fact]
    public void HasTrigger_NoTriggersDeclared_ReturnsFalse()
    {
        // Arrange
        WorkflowStructure structure = WorkflowStructure.Empty;

        // Act
        bool matched = structure.HasTrigger("push");

        // Assert
        Assert.False(matched);
    }

    // --------------------------------------------------------------- IsAction

    [Theory]
    [InlineData("actions/checkout@v4", true)]
    [InlineData("actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3", true)]
    [InlineData("actions/checkout", true)]
    [InlineData("ACTIONS/CHECKOUT@v4", true)]
    [InlineData("actions/checkout-buildx@v1", false)]
    [InlineData("actions/checkoutv4", false)]
    [InlineData("my-org/actions/checkout@v1", false)]
    [InlineData("actions/setup-node@v4", false)]
    public void IsAction_UsesReferenceVariants_MatchesOnlyTheExactOwnerAndRepository(
        string uses,
        bool expected)
    {
        // Arrange. `actions/checkout-buildx` is the case that matters: a prefix
        // test without the `@` boundary would treat a different action as
        // checkout and pin the wrong thing.
        WorkflowStructuredStep step = Step(uses, 7);

        // Act
        bool matched = step.IsAction("actions", "checkout");

        // Assert
        Assert.Equal(expected, matched);
    }

    [Fact]
    public void IsAction_StepRunsAScriptAndHasNoUses_ReturnsFalseWithoutThrowing()
    {
        // Arrange. A `run:` step carries a null Uses.
        WorkflowStructuredStep step = Step(uses: null, line: 11);

        // Act
        bool matched = step.IsAction("actions", "checkout");

        // Assert
        Assert.False(matched);
        Assert.Null(step.Uses);
        Assert.Null(step.UsesLine);
    }

    // ------------------------------------------------------------------ Input

    [Fact]
    public void Input_NameDiffersOnlyByCase_ReturnsTheValueAndItsSourceLine()
    {
        // Arrange. Workflow authors write `script:` and `SCRIPT:`; the reader
        // stores whatever was written, so lookup has to be case-insensitive or
        // the rule misses the input entirely.
        Dictionary<string, WorkflowInputValue> with =
            new(StringComparer.OrdinalIgnoreCase)
            {
                ["SCRIPT"] = new("console.log(1)", 14)
            };

        WorkflowStructuredStep step = Step("actions/github-script@v7", 11, with);

        // Act
        WorkflowInputValue? value = step.Input("script");

        // Assert
        Assert.Equal(new WorkflowInputValue("console.log(1)", 14), value);
    }

    [Fact]
    public void Input_NameIsNotPresent_ReturnsNullRatherThanAnEmptyValue()
    {
        // Arrange
        WorkflowStructuredStep step = Step("actions/checkout@v4", 9);

        // Act
        WorkflowInputValue? value = step.Input("persist-credentials");

        // Assert
        Assert.Null(value);
    }
}
