using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Rules;

/// <summary>
/// Reports a self-hosted runner reachable from a pull-request trigger.
///
/// Self-hosted runners are not disposable. A job that runs contributor-supplied
/// code on one leaves whatever it did behind for the next job — modified tools
/// on the PATH, poisoned caches, credentials read from the host. GitHub's own
/// guidance is not to use self-hosted runners for public pull requests, and a
/// pull-request trigger is the point at which untrusted code reaches them.
/// </summary>
public sealed class SelfHostedRunnerRule : IWorkflowSecurityRule
{
    public string RuleId => "GHA010";

    public string Title =>
        "Self-hosted runner is reachable from a pull-request trigger";

    public WorkflowSeverity Severity => WorkflowSeverity.High;

    public IReadOnlyList<WorkflowFinding> Evaluate(ParsedWorkflow workflow)
    {
        bool pullRequestTriggered =
            workflow.Structure.HasTrigger("pull_request");

        if (!pullRequestTriggered)
        {
            return [];
        }

        return workflow.Structure.Jobs
            .Where(job =>
                job.RunsOn is not null &&
                job.RunsOn.Contains("self-hosted", StringComparison.OrdinalIgnoreCase))
            .Select(job => new WorkflowFinding(
                RuleId,
                Severity,
                Title,
                $"Job '{job.Name}' runs on a self-hosted runner in a workflow a " +
                "pull request can trigger. The runner persists between jobs, so " +
                "anything contributor code changes on it outlives the run.",
                job.RunsOnLine ?? job.Line,
                "Use a GitHub-hosted runner for pull-request workflows, or gate the " +
                "job behind an environment that requires review before it runs.",
                false))
            .ToArray();
    }
}
