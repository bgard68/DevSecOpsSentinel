using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Application;

public sealed record WorkflowParseResult(
    bool IsValid,
    ParsedWorkflow? Workflow,
    IReadOnlyList<string> Errors)
{
    public static WorkflowParseResult Success(ParsedWorkflow workflow) =>
        new(true, workflow, Array.Empty<string>());

    public static WorkflowParseResult Failure(params string[] errors) =>
        new(false, null, errors);
}
