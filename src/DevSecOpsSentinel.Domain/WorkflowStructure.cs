namespace DevSecOpsSentinel.Domain;

/// <summary>
/// The workflow as a document structure, with the source line of every element.
///
/// This exists alongside <see cref="ParsedWorkflow.Lines"/> rather than replacing
/// it. Structure answers questions about relationships — which inputs belong to
/// which step, which permissions belong to which job — that indentation
/// arithmetic answers only approximately. Lines remain the substrate for content
/// inside block scalars, which YAML models as a single opaque scalar, and for
/// line-indexed patching.
/// </summary>
public sealed record WorkflowStructure(
    IReadOnlyList<string> Triggers,
    IReadOnlyList<WorkflowPermissionEntry> Permissions,
    IReadOnlyList<WorkflowStructuredJob> Jobs)
{
    public static WorkflowStructure Empty { get; } = new([], [], []);

    /// <summary>Workflow-level and job-level permissions together.</summary>
    public IEnumerable<WorkflowPermissionEntry> AllPermissions =>
        Permissions.Concat(Jobs.SelectMany(job => job.Permissions));

    public IEnumerable<WorkflowStructuredStep> AllSteps =>
        Jobs.SelectMany(job => job.Steps);
}

/// <summary>
/// One permission grant. <paramref name="Name"/> is empty for the scalar form
/// <c>permissions: write-all</c>, where the value stands alone.
/// </summary>
public sealed record WorkflowPermissionEntry(
    string Name,
    string Value,
    int Line);

public sealed record WorkflowStructuredJob(
    string Name,
    int Line,
    int? TimeoutLine,
    IReadOnlyList<WorkflowPermissionEntry> Permissions,
    IReadOnlyList<WorkflowStructuredStep> Steps);

public sealed record WorkflowStructuredStep(
    string? Uses,
    int Line,
    int? UsesLine,
    IReadOnlyDictionary<string, WorkflowInputValue> With)
{
    public bool IsAction(string owner, string repository) =>
        Uses is not null &&
        (Uses.StartsWith($"{owner}/{repository}@", StringComparison.OrdinalIgnoreCase) ||
         Uses.Equals($"{owner}/{repository}", StringComparison.OrdinalIgnoreCase));

    public WorkflowInputValue? Input(string name) =>
        With.TryGetValue(name, out WorkflowInputValue? value) ? value : null;
}

public sealed record WorkflowInputValue(string Value, int Line);
