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

        string[] rawLines = document.Content.Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n')
            .Split('\n');

        List<WorkflowLine> lines = [];
        for (int index = 0; index < rawLines.Length; index++)
        {
            string raw = rawLines[index].Replace("\t", "    ", StringComparison.Ordinal);
            string trimmed = raw.Trim();
            int indent = raw.Length - raw.TrimStart().Length;
            lines.Add(new WorkflowLine(index + 1, indent, trimmed));
        }

        WorkflowLine[] meaningfulLines = lines
            .Where(line => line.Text.Length > 0 && !line.Text.StartsWith('#'))
            .ToArray();
        if (!meaningfulLines.Any(line => line.Text.Contains(':')))
        {
            return WorkflowParseResult.Failure("Workflow content does not contain a YAML mapping.");
        }

        if (!meaningfulLines.Any(line => line.Text.Equals("jobs:", StringComparison.Ordinal)))
        {
            return WorkflowParseResult.Failure("A GitHub Actions workflow must define jobs.");
        }

        IReadOnlyList<string> triggers = ParseTriggers(lines);
        IReadOnlyList<WorkflowJob> jobs = ParseJobs(lines);
        return WorkflowParseResult.Success(new ParsedWorkflow(document, lines, jobs, triggers));
    }

    private static IReadOnlyList<string> ParseTriggers(IReadOnlyList<WorkflowLine> lines)
    {
        List<string> triggers = [];
        WorkflowLine? onLine = lines.FirstOrDefault(line => line.Text.StartsWith("on:", StringComparison.Ordinal));
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

        foreach (WorkflowLine line in lines.Where(line => line.Number > onLine.Number))
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

    private static IReadOnlyList<WorkflowJob> ParseJobs(IReadOnlyList<WorkflowLine> lines)
    {
        WorkflowLine? jobsLine = lines.FirstOrDefault(line => line.Text.Equals("jobs:", StringComparison.Ordinal));
        if (jobsLine is null)
        {
            return Array.Empty<WorkflowJob>();
        }

        List<WorkflowJob> jobs = [];
        List<WorkflowLine> jobDeclarations = lines
            .Where(line => line.Number > jobsLine.Number && line.Indent > jobsLine.Indent &&
                line.Text.EndsWith(':') && !line.Text.StartsWith('-'))
            .Where(line => !line.Text.StartsWith("steps:", StringComparison.Ordinal) &&
                !line.Text.StartsWith("permissions:", StringComparison.Ordinal))
            .ToList();

        int? expectedIndent = jobDeclarations.Count > 0 ? jobDeclarations.Min(line => line.Indent) : null;
        if (expectedIndent is null)
        {
            return jobs;
        }

        WorkflowLine[] topLevelJobs = jobDeclarations.Where(line => line.Indent == expectedIndent.Value).ToArray();
        for (int index = 0; index < topLevelJobs.Length; index++)
        {
            WorkflowLine declaration = topLevelJobs[index];
            int endLine = index + 1 < topLevelJobs.Length ? topLevelJobs[index + 1].Number : int.MaxValue;
            int? timeoutLine = lines
                .Where(line => line.Number > declaration.Number && line.Number < endLine &&
                    line.Indent > declaration.Indent && line.Text.StartsWith("timeout-minutes:", StringComparison.Ordinal))
                .Select(line => (int?)line.Number)
                .FirstOrDefault();

            jobs.Add(new WorkflowJob(
                declaration.Text.TrimEnd(':').Trim(),
                declaration.Number,
                declaration.Indent,
                timeoutLine));
        }

        return jobs;
    }
}
