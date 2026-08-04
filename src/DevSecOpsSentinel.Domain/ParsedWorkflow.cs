namespace DevSecOpsSentinel.Domain;

public sealed record ParsedWorkflow(
    WorkflowDocument Document,
    IReadOnlyList<WorkflowLine> Lines,
    IReadOnlyList<WorkflowJob> Jobs,
    IReadOnlyList<string> Triggers)
{
    /// <summary>
    /// Bodies of <c>run:</c> and <c>script:</c> block scalars, which are excluded
    /// from <see cref="Lines"/> because their content is shell or JavaScript rather
    /// than YAML. Rules that reason about script content read them from here.
    /// </summary>
    public IReadOnlyList<WorkflowScriptBlock> ScriptBlocks { get; init; } = [];
}

public sealed record WorkflowLine(int Number, int Indent, string Text);

/// <summary>
/// A block scalar whose content is executed rather than interpreted as YAML.
/// <paramref name="Key"/> is the mapping key that introduced it, currently
/// <c>run</c> or <c>script</c>.
/// </summary>
public sealed record WorkflowScriptBlock(
    string Key,
    int HeaderLine,
    IReadOnlyList<WorkflowLine> Content);

public sealed record WorkflowJob(
    string Name,
    int DeclarationLine,
    int Indent,
    int? TimeoutLine);
