using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Application;

public interface IRemediationReportService
{
    RemediationReport Build(WorkflowDocument document);
}
