using DevSecOpsSentinel.Domain;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace DevSecOpsSentinel.Infrastructure;

/// <summary>
/// Builds a <see cref="WorkflowStructure"/> from workflow YAML.
///
/// Structure is read with a real YAML parser so that anchors, aliases, flow
/// mappings, quoted keys and the YAML 1.1 treatment of <c>on</c> as a boolean all
/// resolve the way GitHub resolves them, rather than the way indentation
/// arithmetic guesses they resolve.
/// </summary>
internal static class YamlWorkflowStructureReader
{
    public static bool TryRead(
        string content,
        out WorkflowStructure structure,
        out string? error)
    {
        structure = WorkflowStructure.Empty;
        error = null;

        try
        {
            YamlStream stream = [];
            using StringReader reader = new(content);
            stream.Load(reader);

            if (stream.Documents.Count == 0 ||
                stream.Documents[0].RootNode is not YamlMappingNode root)
            {
                return true;
            }

            structure = new WorkflowStructure(
                ReadTriggers(root),
                ReadPermissions(Value(root, "permissions")),
                ReadJobs(Value(root, "jobs") as YamlMappingNode))
            {
                PermissionsDeclared = Value(root, "permissions") is not null
            };

            return true;
        }
        catch (YamlException exception)
        {
            error = exception.Message;
            return false;
        }
    }

    private static IReadOnlyList<string> ReadTriggers(YamlMappingNode root)
    {
        // YAML 1.1 resolves an unquoted `on` to the boolean true, so a workflow
        // written the ordinary way can surface under either key depending on the
        // emitter that produced it.
        YamlNode? triggers =
            Value(root, "on") ??
            Value(root, "true") ??
            Value(root, "True");

        return triggers switch
        {
            YamlScalarNode scalar when scalar.Value is { Length: > 0 } =>
                [scalar.Value],

            YamlSequenceNode sequence =>
                sequence.Children
                    .OfType<YamlScalarNode>()
                    .Select(child => child.Value ?? string.Empty)
                    .Where(value => value.Length > 0)
                    .ToArray(),

            YamlMappingNode mapping =>
                mapping.Children.Keys
                    .OfType<YamlScalarNode>()
                    .Select(key => key.Value ?? string.Empty)
                    .Where(value => value.Length > 0)
                    .ToArray(),

            _ => []
        };
    }

    private static IReadOnlyList<WorkflowPermissionEntry> ReadPermissions(
        YamlNode? permissions)
    {
        switch (permissions)
        {
            // permissions: write-all
            case YamlScalarNode scalar when scalar.Value is { Length: > 0 }:
                return
                [
                    new WorkflowPermissionEntry(
                        string.Empty,
                        scalar.Value,
                        LineOf(scalar))
                ];

            // permissions:
            //   contents: write
            case YamlMappingNode mapping:
                return mapping.Children
                    .Where(child =>
                        child.Key is YamlScalarNode &&
                        child.Value is YamlScalarNode)
                    .Select(child => new WorkflowPermissionEntry(
                        ((YamlScalarNode)child.Key).Value ?? string.Empty,
                        ((YamlScalarNode)child.Value).Value ?? string.Empty,
                        LineOf(child.Value)))
                    .ToArray();

            default:
                return [];
        }
    }

    private static IReadOnlyList<WorkflowStructuredJob> ReadJobs(
        YamlMappingNode? jobs)
    {
        if (jobs is null)
        {
            return [];
        }

        List<WorkflowStructuredJob> results = [];

        foreach (KeyValuePair<YamlNode, YamlNode> entry in jobs.Children)
        {
            if (entry.Key is not YamlScalarNode name ||
                entry.Value is not YamlMappingNode job)
            {
                continue;
            }

            YamlNode? runsOn = Value(job, "runs-on");
            YamlNode? secrets = Value(job, "secrets");

            results.Add(new WorkflowStructuredJob(
                name.Value ?? string.Empty,
                LineOf(entry.Key),
                Value(job, "timeout-minutes") is { } timeout
                    ? LineOf(timeout)
                    : null,
                ReadPermissions(Value(job, "permissions")),
                ReadSteps(Value(job, "steps") as YamlSequenceNode))
            {
                PermissionsDeclared = Value(job, "permissions") is not null,
                RunsOn = FlattenScalar(runsOn),
                RunsOnLine = runsOn is null ? null : LineOf(runsOn),
                Uses = (Value(job, "uses") as YamlScalarNode)?.Value,
                Secrets = FlattenScalar(secrets),
                SecretsLine = secrets is null ? null : LineOf(secrets)
            });
        }

        return results;
    }

    private static IReadOnlyList<WorkflowStructuredStep> ReadSteps(
        YamlSequenceNode? steps)
    {
        if (steps is null)
        {
            return [];
        }

        List<WorkflowStructuredStep> results = [];

        foreach (YamlNode node in steps.Children)
        {
            if (node is not YamlMappingNode step)
            {
                continue;
            }

            YamlScalarNode? usesNode = Value(step, "uses") as YamlScalarNode;
            string? uses = usesNode?.Value;

            Dictionary<string, WorkflowInputValue> inputs =
                new(StringComparer.OrdinalIgnoreCase);

            if (Value(step, "with") is YamlMappingNode with)
            {
                foreach (KeyValuePair<YamlNode, YamlNode> input in with.Children)
                {
                    if (input.Key is YamlScalarNode key &&
                        key.Value is { Length: > 0 } name &&
                        input.Value is YamlScalarNode value)
                    {
                        inputs[name] = new WorkflowInputValue(
                            value.Value ?? string.Empty,
                            LineOf(input.Value));
                    }
                }
            }

            results.Add(new WorkflowStructuredStep(
                uses,
                LineOf(node),
                usesNode is null ? null : LineOf(usesNode),
                inputs));
        }

        return results;
    }

    /// <summary>
    /// Renders a scalar, or a sequence of scalars, as one comparable string.
    /// <c>runs-on</c> accepts both forms, and a label list such as
    /// <c>[self-hosted, linux]</c> has to be matchable as a whole.
    /// </summary>
    private static string? FlattenScalar(YamlNode? node) => node switch
    {
        YamlScalarNode scalar => scalar.Value,

        YamlSequenceNode sequence => string.Join(
            ",",
            sequence.Children
                .OfType<YamlScalarNode>()
                .Select(child => child.Value ?? string.Empty)),

        YamlMappingNode mapping => string.Join(
            ",",
            mapping.Children.Values
                .OfType<YamlScalarNode>()
                .Select(child => child.Value ?? string.Empty)),

        _ => null
    };

    private static YamlNode? Value(YamlMappingNode mapping, string key) =>
        mapping.Children.FirstOrDefault(child =>
            child.Key is YamlScalarNode scalar &&
            string.Equals(scalar.Value, key, StringComparison.OrdinalIgnoreCase))
            .Value;

    private static int LineOf(YamlNode node) => (int)node.Start.Line;
}
