using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Application;

public interface IWorkflowPatchGenerator
{
    Task<WorkflowPatch> GenerateAsync(
        ParsedWorkflow workflow,
        IReadOnlyList<WorkflowFinding> findings,
        CancellationToken cancellationToken);
}
