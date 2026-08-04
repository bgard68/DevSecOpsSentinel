using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Application;

public interface IRemediationReportService
{
    Task<RemediationReport> BuildAsync(
        WorkflowDocument document,
        CancellationToken cancellationToken);
}
