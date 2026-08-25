using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Application;

public sealed class WorkflowAnalysisService(
    IWorkflowParser parser,
    IEnumerable<IWorkflowSecurityRule> rules,
    IWorkflowPatchGenerator patchGenerator)
    : IWorkflowAnalysisService
{
    public async Task<WorkflowAnalysisResult> AnalyzeAsync(
        WorkflowDocument document,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(document);

        WorkflowParseResult parseResult = parser.Parse(document);
        if (!parseResult.IsValid || parseResult.Workflow is null)
        {
            return new WorkflowAnalysisResult(
                document.FileName,
                false,
                parseResult.Errors,
                Array.Empty<WorkflowFinding>(),
                null);
        }

        WorkflowFinding[] findings = rules
            .SelectMany(rule => rule.Evaluate(parseResult.Workflow))
            .OrderByDescending(finding => finding.Severity)
            .ThenBy(finding =>
                finding.LineNumber ?? int.MaxValue)
            .ThenBy(
                finding => finding.RuleId,
                StringComparer.Ordinal)
            .ToArray();

        WorkflowPatch patch =
            await patchGenerator.GenerateAsync(
                parseResult.Workflow,
                findings,
                cancellationToken);

        WorkflowAcknowledgement[] acknowledgements = rules
            .SelectMany(rule => rule.Acknowledge(parseResult.Workflow))
            .OrderBy(entry => entry.LineNumber ?? int.MaxValue)
            .ThenBy(entry => entry.RuleId, StringComparer.Ordinal)
            .ToArray();

        return new WorkflowAnalysisResult(
            document.FileName,
            true,
            Array.Empty<string>(),
            findings,
            patch)
        {
            Acknowledgements = acknowledgements
        };
    }
}
