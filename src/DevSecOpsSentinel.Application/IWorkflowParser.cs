using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Application;

public interface IWorkflowParser
{
    WorkflowParseResult Parse(WorkflowDocument document);
}
