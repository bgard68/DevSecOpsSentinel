using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Rules;

/// <summary>
/// Associates each <c>uses:</c> step with the <c>with:</c> inputs that belong to
/// it, by indentation.
///
/// Rules that only classify individual lines do not need this. Rules that reason
/// about a step as a unit — what action it runs and how it was configured — do,
/// and reconstructing that relationship from a line list is the point at which
/// the line-oriented parser starts working against the grain.
/// </summary>
internal static class WorkflowStepReader
{
    public static IReadOnlyList<WorkflowUsesStep> ReadUsesSteps(
        ParsedWorkflow workflow)
    {
        List<WorkflowUsesStep> steps = [];
        IReadOnlyList<WorkflowLine> lines = workflow.Lines;

        for (int index = 0; index < lines.Count; index++)
        {
            WorkflowLine line = lines[index];

            if (TryReadUses(line, out string actionReference, out int keyIndent))
            {
                steps.Add(ReadStep(
                    lines,
                    index,
                    line,
                    actionReference,
                    keyIndent));
            }
        }

        return steps;
    }

    private static WorkflowUsesStep ReadStep(
        IReadOnlyList<WorkflowLine> lines,
        int usesIndex,
        WorkflowLine usesLine,
        string actionReference,
        int keyIndent)
    {
        Dictionary<string, WorkflowLine> inputs =
            new(StringComparer.OrdinalIgnoreCase);

        bool sawWithBlock = false;
        int? withIndent = null;

        for (int index = usesIndex + 1; index < lines.Count; index++)
        {
            WorkflowLine line = lines[index];

            if (IsOutsideStep(line, usesLine, keyIndent))
            {
                break;
            }

            if (withIndent is not null)
            {
                if (line.Indent > withIndent.Value)
                {
                    int colonIndex = line.Text.IndexOf(':');
                    if (colonIndex > 0)
                    {
                        inputs[line.Text[..colonIndex].Trim()] = line;
                    }

                    continue;
                }

                withIndent = null;
            }

            if (line.Indent == keyIndent &&
                line.Text.Equals("with:", StringComparison.OrdinalIgnoreCase))
            {
                sawWithBlock = true;
                withIndent = line.Indent;
            }
        }

        return new WorkflowUsesStep(
            usesLine,
            actionReference,
            sawWithBlock,
            inputs);
    }

    /// <summary>
    /// A step ends at the first line that dedents past its keys, or at the next
    /// sequence item at the same level.
    /// </summary>
    private static bool IsOutsideStep(
        WorkflowLine line,
        WorkflowLine usesLine,
        int keyIndent) =>
        line.Indent < keyIndent ||
        (line.Text.StartsWith("- ", StringComparison.Ordinal) &&
         line.Indent <= usesLine.Indent);

    private static bool TryReadUses(
        WorkflowLine line,
        out string actionReference,
        out int keyIndent)
    {
        actionReference = string.Empty;
        keyIndent = line.Indent;

        string text = line.Text;

        if (text.StartsWith("- ", StringComparison.Ordinal))
        {
            text = text[2..].TrimStart();

            // The key sits two columns right of the sequence dash.
            keyIndent = line.Indent + 2;
        }

        if (!text.StartsWith("uses:", StringComparison.Ordinal))
        {
            return false;
        }

        actionReference = text["uses:".Length..].Trim();

        int commentIndex = actionReference.IndexOf('#');
        if (commentIndex >= 0)
        {
            actionReference = actionReference[..commentIndex].TrimEnd();
        }

        return actionReference.Length > 0;
    }
}

internal sealed record WorkflowUsesStep(
    WorkflowLine UsesLine,
    string ActionReference,
    bool HasWithBlock,
    IReadOnlyDictionary<string, WorkflowLine> Inputs)
{
    public bool IsAction(string owner, string repository) =>
        ActionReference.StartsWith(
            $"{owner}/{repository}@",
            StringComparison.OrdinalIgnoreCase) ||
        ActionReference.Equals(
            $"{owner}/{repository}",
            StringComparison.OrdinalIgnoreCase);

    public string? InputValue(string name) =>
        Inputs.TryGetValue(name, out WorkflowLine? line)
            ? ValueOf(line)
            : null;

    public WorkflowLine? InputLine(string name) =>
        Inputs.TryGetValue(name, out WorkflowLine? line) ? line : null;

    private static string ValueOf(WorkflowLine line)
    {
        int colonIndex = line.Text.IndexOf(':');
        return colonIndex < 0
            ? string.Empty
            : line.Text[(colonIndex + 1)..].Trim();
    }
}
