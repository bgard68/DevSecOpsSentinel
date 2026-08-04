using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Rules;

/// <summary>
/// Reports <c>actions/checkout</c> steps that leave the job token on disk.
///
/// The action defaults <c>persist-credentials</c> to true, which writes the
/// GITHUB_TOKEN into <c>.git/config</c> on the runner. Every later step in the
/// job can read it, including third-party actions and anything a build script
/// executes, so a compromise anywhere after checkout inherits repository write
/// access rather than being confined to the step it started in.
/// </summary>
public sealed class PersistedCredentialsRule : IWorkflowSecurityRule
{
    public string RuleId => "GHA006";

    public string Title =>
        "Checkout leaves the job token readable on the runner";

    public WorkflowSeverity Severity => WorkflowSeverity.Medium;

    public IReadOnlyList<WorkflowFinding> Evaluate(ParsedWorkflow workflow) =>
        WorkflowStepReader.ReadUsesSteps(workflow)
            .Where(step => step.IsAction("actions", "checkout"))
            .Where(LeavesCredentialsOnDisk)
            .Select(step => new WorkflowFinding(
                RuleId,
                Severity,
                Title,
                "actions/checkout defaults persist-credentials to true, so the " +
                "job token is written to .git/config and stays readable by every " +
                "later step in the job.",
                (step.InputLine("persist-credentials") ?? step.UsesLine).Number,
                "Set persist-credentials: false unless a later step needs to push " +
                "with the job token.",
                false))
            .ToArray();

    private static bool LeavesCredentialsOnDisk(WorkflowUsesStep step)
    {
        string? configured = step.InputValue("persist-credentials");

        // Absent means the action's default, which is true.
        return configured is null ||
            configured.Equals("true", StringComparison.OrdinalIgnoreCase);
    }
}
