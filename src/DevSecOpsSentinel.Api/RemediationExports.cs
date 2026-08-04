using System.Text;
using System.Text.Json;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Api;

internal static class RemediationExports
{
    public static string Markdown(RemediationReport report)
    {
        StringBuilder text = new();
        text.AppendLine($"# DevSecOps Sentinel Remediation Report — {report.FileName}");
        text.AppendLine();
        text.AppendLine($"- Findings before: {report.OriginalAnalysis.FindingCount}");
        text.AppendLine($"- Findings after: {report.ProposedAnalysis.FindingCount}");
        text.AppendLine($"- Risk reduction: {report.RiskReductionPercent}%");
        text.AppendLine($"- Patch valid: {report.PatchValid}");
        text.AppendLine();
        text.AppendLine("## Changes");
        foreach (RemediationChange change in report.Changes)
            text.AppendLine($"- **{change.RuleId} — {change.Title}**: {(change.Resolved ? "Resolved" : "Still present")}");
        text.AppendLine();
        text.AppendLine("## Unified diff");
        text.AppendLine("```diff");
        foreach (string line in report.UnifiedDiff) text.AppendLine(line);
        text.AppendLine("```");
        return text.ToString();
    }

    public static string Html(RemediationReport report)
    {
        string changes = string.Join("", report.Changes.Select(change => $"<li><strong>{Encode(change.RuleId)} — {Encode(change.Title)}</strong>: {(change.Resolved ? "Resolved" : "Still present")}</li>"));
        string diff = Encode(string.Join("\n", report.UnifiedDiff));
        return $"<!doctype html><html><head><meta charset=\"utf-8\"><title>Remediation report</title><style>body{{font-family:system-ui;max-width:1000px;margin:40px auto;padding:0 24px}}pre{{background:#0d1117;color:#e6edf3;padding:20px;overflow:auto}}.metric{{display:inline-block;margin-right:24px}}</style></head><body><h1>DevSecOps Sentinel Remediation Report</h1><h2>{Encode(report.FileName)}</h2><p class=\"metric\"><strong>{report.OriginalAnalysis.FindingCount}</strong> findings before</p><p class=\"metric\"><strong>{report.ProposedAnalysis.FindingCount}</strong> findings after</p><p class=\"metric\"><strong>{report.RiskReductionPercent}%</strong> risk reduction</p><h2>Changes</h2><ul>{changes}</ul><h2>Unified diff</h2><pre>{diff}</pre></body></html>";
    }

    public static object Sarif(RemediationReport report) => new
    {
        version = "2.1.0",
        schema = "https://json.schemastore.org/sarif-2.1.0.json",
        runs = new[]
        {
            new
            {
                tool = new { driver = new { name = "DevSecOps Sentinel", version = "1.0.0" } },
                results = report.OriginalAnalysis.Findings.Select(finding => new
                {
                    ruleId = finding.RuleId,
                    level = finding.Severity.ToString().ToLowerInvariant(),
                    message = new { text = finding.Description },
                    locations = finding.LineNumber is null ? Array.Empty<object>() : new object[]
                    {
                        new { physicalLocation = new { artifactLocation = new { uri = report.FileName }, region = new { startLine = finding.LineNumber } } }
                    }
                }).ToArray()
            }
        }
    };

    public static string Json(RemediationReport report) => JsonSerializer.Serialize(report, new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true });
    private static string Encode(string value) => System.Net.WebUtility.HtmlEncode(value);
}
