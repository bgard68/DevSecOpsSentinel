namespace DevSecOpsSentinel.Domain;

public sealed record ParsedWorkflow(
    WorkflowDocument Document,
    IReadOnlyList<WorkflowLine> Lines,
    IReadOnlyList<WorkflowJob> Jobs,
    IReadOnlyList<string> Triggers);

public sealed record WorkflowLine(int Number, int Indent, string Text);

public sealed record WorkflowJob(
    string Name,
    int DeclarationLine,
    int Indent,
    int? TimeoutLine);
