using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Application;

public interface IWorkflowAnalysisService
{
    Task<WorkflowAnalysisResult> AnalyzeAsync(
        WorkflowDocument document,
        CancellationToken cancellationToken);
}
