using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Rules;

/// <summary>
/// Reports <c>actions/checkout</c> steps that leave the job token on disk where
/// nothing in the job goes on to use it.
///
/// The action defaults <c>persist-credentials</c> to true, which writes the
/// GITHUB_TOKEN into <c>.git/config</c> on the runner. Every later step in the
/// job can read it, including third-party actions and anything a build script
/// executes, so a compromise anywhere after checkout inherits repository write
/// access rather than being confined to the step it started in.
///
/// The exception was already written into this rule's own remediation - "unless
/// a later step needs to push with the job token" - while nothing established
/// whether one did. A release job that runs <c>git push</c> needs exactly what
/// the finding told it to remove, so the advice could not be followed and the
/// finding could not be closed.
///
/// The signal is deliberately narrow. Suppressing this finding wrongly leaves a
/// real credential exposure unreported, which is far more expensive than one
/// more line of noise, so only <c>git push</c> in a later script in the same job
/// counts: it is the one case that unambiguously reads the credentials this
/// finding is about. A step that pushes through an explicit remote URL, or an
/// action that authenticates with its own token input, does not need the
/// persisted credential and is still reported.
/// </summary>
public sealed class PersistedCredentialsRule : IWorkflowSecurityRule
{
    public string RuleId => "GHA006";
    public string Title =>
        "Checkout leaves the job token readable on the runner";
    public WorkflowSeverity Severity => WorkflowSeverity.Medium;

    public IReadOnlyList<WorkflowFinding> Evaluate(ParsedWorkflow workflow)
    {
        List<WorkflowFinding> findings = [];

        foreach (WorkflowStructuredJob job in workflow.Structure.Jobs)
        {
            int jobEnd = EndOfJob(workflow, job);

            foreach (WorkflowStructuredStep step in job.Steps)
            {
                if (!step.IsAction("actions", "checkout") ||
                    !LeavesCredentialsOnDisk(step) ||
                    PushesLater(workflow, step, jobEnd))
                {
                    continue;
                }

                findings.Add(new WorkflowFinding(
                    RuleId,
                    Severity,
                    Title,
                    "actions/checkout defaults persist-credentials to true, so the " +
                    "job token is written to .git/config and stays readable by every " +
                    "later step in the job. Nothing in this job pushes with it.",
                    step.Input("persist-credentials")?.Line
                        ?? step.UsesLine
                        ?? step.Line,
                    "Set persist-credentials: false unless a later step needs to push " +
                    "with the job token.",
                    false));
            }
        }

        return findings;
    }

    /// <summary>
    /// The checkouts this rule accepted because the job goes on to push with the
    /// credential they left behind.
    /// </summary>
    public IReadOnlyList<WorkflowAcknowledgement> Acknowledge(ParsedWorkflow workflow)
    {
        List<WorkflowAcknowledgement> accepted = [];

        foreach (WorkflowStructuredJob job in workflow.Structure.Jobs)
        {
            int jobEnd = EndOfJob(workflow, job);

            foreach (WorkflowStructuredStep step in job.Steps)
            {
                if (!step.IsAction("actions", "checkout") ||
                    !LeavesCredentialsOnDisk(step) ||
                    !PushesLater(workflow, step, jobEnd))
                {
                    continue;
                }

                accepted.Add(new WorkflowAcknowledgement(
                    RuleId,
                    "The persisted credential is used, not merely left behind",
                    $"A later step in job '{job.Name}' pushes with the job token, so "
                        + "persist-credentials must stay true here. Setting it false "
                        + "would break the push, so it is not reported.",
                    step.UsesLine ?? step.Line));
            }
        }

        return accepted;
    }

    private static bool LeavesCredentialsOnDisk(WorkflowStructuredStep step)
    {
        WorkflowInputValue? configured = step.Input("persist-credentials");

        // Absent means the action's default, which is true.
        return configured is null ||
            configured.Value.Equals("true", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Whether a script after this checkout, and still inside the same job,
    /// pushes with the credentials the checkout left behind.
    ///
    /// Scripts are matched by line span rather than by step, because a block
    /// scalar's body is withheld from the structure - it is shell, not YAML.
    /// Ordering matters: a push in an earlier job, or before the checkout in this
    /// one, is not using this checkout's credentials.
    /// </summary>
    private static bool PushesLater(
        ParsedWorkflow workflow,
        WorkflowStructuredStep checkout,
        int jobEnd) =>
        workflow.ScriptBlocks
            .Where(block => block.HeaderLine > checkout.Line && block.HeaderLine <= jobEnd)
            .SelectMany(block => block.Content)
            .Select(line => line.Text)
            .Concat(workflow.Lines
                .Where(line => line.Number > checkout.Line && line.Number <= jobEnd)
                .Where(line => IsInlineScript(line.Text))
                .Select(line => line.Text))
            .Any(IsGitPush);

    /// <summary>
    /// A single-line <c>run:</c> value, which the parser leaves among the YAML
    /// lines rather than collecting as a block scalar.
    ///
    /// Only script text is searched. Scanning every line in the job's span would
    /// let a step named "Set up git push credentials" suppress the finding, and a
    /// wrong suppression here hides a real credential exposure.
    /// </summary>
    private static bool IsInlineScript(string text) =>
        text.StartsWith("run:", StringComparison.OrdinalIgnoreCase) ||
        text.StartsWith("- run:", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// A <c>git push</c> invocation, allowing the options that commonly sit
    /// between the two words, such as <c>git -C site push</c>.
    /// </summary>
    private static bool IsGitPush(string text)
    {
        int git = text.IndexOf("git ", StringComparison.OrdinalIgnoreCase);
        if (git < 0)
        {
            return false;
        }

        int push = text.IndexOf(" push", git, StringComparison.OrdinalIgnoreCase);
        return push > git;
    }

    /// <summary>
    /// The last line belonging to this job: the line before the next job starts,
    /// or the end of the document for the final job.
    /// </summary>
    private static int EndOfJob(ParsedWorkflow workflow, WorkflowStructuredJob job)
    {
        int next = workflow.Structure.Jobs
            .Select(candidate => candidate.Line)
            .Where(line => line > job.Line)
            .DefaultIfEmpty(int.MaxValue)
            .Min();

        return next == int.MaxValue ? int.MaxValue : next - 1;
    }
}
