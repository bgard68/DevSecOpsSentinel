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

    /// <summary>
    /// Whether a workflow-level <c>permissions</c> key is present at all.
    ///
    /// Distinct from <see cref="Permissions"/> being empty: <c>permissions: {}</c>
    /// is a key with no entries, and it is the most restrictive grant GitHub
    /// accepts. Counting entries cannot tell the two apart.
    /// </summary>
    public bool PermissionsDeclared { get; init; }

    /// <summary>Workflow-level and job-level permissions together.</summary>
    public IEnumerable<WorkflowPermissionEntry> AllPermissions =>
        Permissions.Concat(Jobs.SelectMany(job => job.Permissions));

    public IEnumerable<WorkflowStructuredStep> AllSteps =>
        Jobs.SelectMany(job => job.Steps);

    /// <summary>
    /// True when neither the workflow nor any job states what the job token may
    /// do, leaving the grant to the repository default.
    ///
    /// Presence of the key is what counts, not the number of entries under it.
    /// A workflow that says <c>permissions: {}</c> has stated its position in
    /// the strongest available terms; reporting that as undeclared would advise
    /// widening a grant that is already empty.
    /// </summary>
    public bool DeclaresNoPermissions =>
        !PermissionsDeclared &&
        Jobs.All(job => !job.PermissionsDeclared);

    /// <summary>
    /// Whether any declared trigger contains <paramref name="name"/>.
    ///
    /// The empty probe is rejected rather than matched. Contains("") holds for
    /// every string, so a rule that passed an unset option would match every
    /// workflow ever scanned instead of failing closed.
    /// </summary>
    public bool HasTrigger(string name) =>
        !string.IsNullOrWhiteSpace(name) &&
        Triggers.Any(trigger =>
            trigger.Contains(name, StringComparison.OrdinalIgnoreCase));

    /// <summary>The workflow-level <c>concurrency</c> block, when one is declared.</summary>
    public WorkflowConcurrency? Concurrency { get; init; }

    /// <summary>The <c>types</c> filters declared on triggers, for triggers that have one.</summary>
    public IReadOnlyList<WorkflowTriggerTypes> TriggerTypes { get; init; } = [];

    /// <summary>
    /// Whether <paramref name="trigger"/> declares <paramref name="type"/> in its
    /// <c>types</c> filter. Exact names, not substrings: <c>closed</c> must not
    /// match a hypothetical <c>unclosed</c>.
    /// </summary>
    public bool TriggerDeclaresType(string trigger, string type) =>
        TriggerTypes.Any(entry =>
            entry.Trigger.Equals(trigger, StringComparison.OrdinalIgnoreCase) &&
            entry.Types.Any(candidate =>
                candidate.Equals(type, StringComparison.OrdinalIgnoreCase)));
}

/// <summary>
/// The workflow-level <c>concurrency</c> block. <paramref name="Group"/> and
/// <paramref name="CancelInProgress"/> hold the raw scalar text, expressions
/// included — rules reason about what the author wrote, not about what one
/// particular event would evaluate it to.
/// </summary>
public sealed record WorkflowConcurrency(
    string? Group,
    string? CancelInProgress,
    int Line);

/// <summary>The <c>types</c> filter declared on one trigger.</summary>
public sealed record WorkflowTriggerTypes(
    string Trigger,
    IReadOnlyList<string> Types);

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
    /// <summary>
    /// Whether this job has a <c>permissions</c> key, empty or otherwise. See
    /// <see cref="WorkflowStructure.PermissionsDeclared"/>.
    /// </summary>
    public bool PermissionsDeclared { get; init; }

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
