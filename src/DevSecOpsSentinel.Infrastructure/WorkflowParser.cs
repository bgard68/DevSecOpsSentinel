using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure;

public sealed class WorkflowParser : IWorkflowParser
{
    public WorkflowParseResult Parse(WorkflowDocument document)
    {
        if (string.IsNullOrWhiteSpace(document.FileName))
        {
            return WorkflowParseResult.Failure("A workflow file name is required.");
        }

        if (string.IsNullOrWhiteSpace(document.Content))
        {
            return WorkflowParseResult.Failure("Workflow content is required.");
        }

        string[] rawLines = document.Content
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n')
            .Split('\n');

        SemanticScan scan = BuildSemanticLines(rawLines);
        List<WorkflowLine> lines = scan.Lines;

        WorkflowLine[] meaningfulLines = lines
            .Where(line => line.Text.Length > 0 && !line.Text.StartsWith('#'))
            .ToArray();

        if (!meaningfulLines.Any(line => line.Text.Contains(':')))
        {
            return WorkflowParseResult.Failure(
                "Workflow content does not contain a YAML mapping.");
        }

        if (!meaningfulLines.Any(line =>
            line.Text.Equals("jobs:", StringComparison.Ordinal)))
        {
            return WorkflowParseResult.Failure(
                "A GitHub Actions workflow must define jobs.");
        }

        // A workflow the YAML parser rejects is one this analyser cannot make
        // authoritative statements about. Reporting the parse error is better
        // than running the line-based rules over it and returning findings that
        // silently omit whatever the malformed region contained.
        if (!YamlWorkflowStructureReader.TryRead(
            document.Content,
            out WorkflowStructure structure,
            out string? yamlError))
        {
            return WorkflowParseResult.Failure(
                $"Workflow YAML is not well formed: {yamlError}");
        }

        IReadOnlyList<string> triggers = structure.Triggers.Count > 0
            ? structure.Triggers
            : ParseTriggers(lines);

        return WorkflowParseResult.Success(
            new ParsedWorkflow(document, lines, triggers)
            {
                ScriptBlocks = scan.ScriptBlocks,
                Structure = structure
            });
    }

    private sealed record SemanticScan(
        List<WorkflowLine> Lines,
        List<WorkflowScriptBlock> ScriptBlocks);

    private static SemanticScan BuildSemanticLines(
        IReadOnlyList<string> rawLines)
    {
        List<WorkflowLine> lines = [];
        List<WorkflowScriptBlock> scriptBlocks = [];

        int? blockScalarHeaderIndent = null;

        // Set while the scanner is inside a run:/script: block scalar. Content
        // is withheld from `lines`, because it is shell or JavaScript rather
        // than YAML, but retained here for rules that analyse script bodies.
        string? scriptKey = null;
        int scriptHeaderLine = 0;
        List<WorkflowLine> scriptContent = [];

        void CloseScriptBlock()
        {
            if (scriptKey is null)
            {
                return;
            }

            scriptBlocks.Add(new WorkflowScriptBlock(
                scriptKey,
                scriptHeaderLine,
                scriptContent.ToArray()));

            scriptKey = null;
            scriptContent = [];
        }

        for (int index = 0; index < rawLines.Count; index++)
        {
            string raw = rawLines[index]
                .Replace("\t", "    ", StringComparison.Ordinal);

            string trimmed = raw.Trim();
            int indent = raw.Length - raw.TrimStart().Length;

            if (blockScalarHeaderIndent is not null)
            {
                if (trimmed.Length == 0)
                {
                    continue;
                }

                if (indent > blockScalarHeaderIndent.Value)
                {
                    if (scriptKey is not null)
                    {
                        scriptContent.Add(
                            new WorkflowLine(index + 1, indent, trimmed));
                    }

                    continue;
                }

                blockScalarHeaderIndent = null;
                CloseScriptBlock();
            }

            WorkflowLine line = new(index + 1, indent, trimmed);
            lines.Add(line);

            if (IsBlockScalarHeader(trimmed))
            {
                blockScalarHeaderIndent = indent;

                if (TryGetScriptKey(trimmed) is { } key)
                {
                    scriptKey = key;
                    scriptHeaderLine = index + 1;
                    scriptContent = [];
                }
            }
        }

        CloseScriptBlock();

        return new SemanticScan(lines, scriptBlocks);
    }

    /// <summary>
    /// Returns the mapping key of a block scalar whose content is executed,
    /// or null when the block is ordinary YAML text such as a description.
    /// </summary>
    private static string? TryGetScriptKey(string trimmedLine)
    {
        string text = trimmedLine;

        if (text.StartsWith("- ", StringComparison.Ordinal))
        {
            text = text[2..].TrimStart();
        }

        int colonIndex = text.IndexOf(':');
        if (colonIndex <= 0)
        {
            return null;
        }

        string key = text[..colonIndex].Trim();

        return key is "run" or "script" ? key : null;
    }

    private static bool IsBlockScalarHeader(string trimmedLine)
    {
        if (trimmedLine.Length == 0 || trimmedLine.StartsWith('#'))
        {
            return false;
        }

        int colonIndex = trimmedLine.IndexOf(':');
        if (colonIndex < 0 || colonIndex == trimmedLine.Length - 1)
        {
            return false;
        }

        string value = trimmedLine[(colonIndex + 1)..].TrimStart();

        if (value.Length == 0 || value[0] is not ('|' or '>'))
        {
            return false;
        }

        string indicator = value[1..];

        int commentIndex = indicator.IndexOf('#');
        if (commentIndex >= 0)
        {
            indicator = indicator[..commentIndex];
        }

        indicator = indicator.Trim();

        return indicator.Length == 0 ||
            indicator is "+" or "-" ||
            (indicator.Length == 1 &&
             indicator[0] is >= '1' and <= '9') ||
            (indicator.Length == 2 &&
             ((indicator[0] is '+' or '-') &&
              indicator[1] is >= '1' and <= '9')) ||
            (indicator.Length == 2 &&
             indicator[0] is >= '1' and <= '9' &&
             indicator[1] is '+' or '-');
    }

    private static IReadOnlyList<string> ParseTriggers(
        IReadOnlyList<WorkflowLine> lines)
    {
        List<string> triggers = [];

        WorkflowLine? onLine = lines.FirstOrDefault(line =>
            line.Text.StartsWith("on:", StringComparison.Ordinal));

        if (onLine is null)
        {
            return triggers;
        }

        string inline = onLine.Text[3..].Trim();
        if (inline.Length > 0)
        {
            triggers.Add(inline.Trim('[', ']', ' '));
            return triggers;
        }

        foreach (WorkflowLine line in lines.Where(line =>
            line.Number > onLine.Number))
        {
            if (line.Text.Length == 0 || line.Text.StartsWith('#'))
            {
                continue;
            }

            if (line.Indent <= onLine.Indent)
            {
                break;
            }

            int colonIndex = line.Text.IndexOf(':');
            if (colonIndex > 0)
            {
                triggers.Add(line.Text[..colonIndex].Trim());
            }
        }

        return triggers;
    }
}
