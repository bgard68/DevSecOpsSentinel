using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Application;

public interface IWorkflowPatchGenerator
{
    WorkflowPatch Generate(
        ParsedWorkflow workflow,
        IReadOnlyList<WorkflowFinding> findings);
}
