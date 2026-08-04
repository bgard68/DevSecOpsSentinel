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

    /// <summary>
    /// True when neither the workflow nor any job states what the job token may
    /// do, leaving the grant to the repository default.
    /// </summary>
    public bool DeclaresNoPermissions =>
        Permissions.Count == 0 &&
        Jobs.All(job => job.Permissions.Count == 0);

    public bool HasTrigger(string name) =>
        Triggers.Any(trigger =>
            trigger.Contains(name, StringComparison.OrdinalIgnoreCase));
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
    IReadOnlyList<WorkflowStructuredStep> Steps)
{
    /// <summary>The <c>runs-on</c> value, with sequence forms joined by a comma.</summary>
    public string? RunsOn { get; init; }

    public int? RunsOnLine { get; init; }

    /// <summary>Set when the job calls a reusable workflow rather than running steps.</summary>
    public string? Uses { get; init; }

    /// <summary>The <c>secrets</c> value on a reusable workflow call, such as <c>inherit</c>.</summary>
    public string? Secrets { get; init; }

    public int? SecretsLine { get; init; }
}

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
