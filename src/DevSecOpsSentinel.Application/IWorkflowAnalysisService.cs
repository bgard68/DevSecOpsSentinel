using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Application;

public interface IWorkflowAnalysisService
{
    WorkflowAnalysisResult Analyze(WorkflowDocument document);
}
