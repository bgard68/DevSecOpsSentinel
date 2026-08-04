using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Api;

internal static class RemediationExports
{
    /// <summary>
    /// Pairs each original finding with whether the proposed patch resolved it.
    /// RemediationReportService builds Changes by projecting over the original
    /// findings, so the two lists are index-aligned.
    /// </summary>
    private static IEnumerable<(WorkflowFinding Finding, bool Resolved)> Detail(
        RemediationReport report) =>
        report.OriginalAnalysis.Findings
            .Select((finding, index) => (
                finding,
                index < report.Changes.Count && report.Changes[index].Resolved));

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
        text.AppendLine("## Findings");
        text.AppendLine();

        if (report.OriginalAnalysis.FindingCount == 0)
        {
            text.AppendLine("No configured rule violations were detected.");
            text.AppendLine();
        }
        else
        {
            // Severity and line are what make this usable as evidence. Listing
            // only the rule name and a resolved flag leaves a reader unable to
            // triage or locate anything.
            text.AppendLine("| Rule | Severity | Line | Status | Finding |");
            text.AppendLine("| --- | --- | --- | --- | --- |");

            foreach ((WorkflowFinding finding, bool resolved) in Detail(report))
            {
                text.AppendLine(
                    $"| {finding.RuleId} " +
                    $"| {finding.Severity} " +
                    $"| {(finding.LineNumber?.ToString() ?? "—")} " +
                    $"| {(resolved ? "Resolved" : "Still present")} " +
                    $"| {finding.Title} |");
            }

            text.AppendLine();
            text.AppendLine("### Detail");
            text.AppendLine();

            foreach ((WorkflowFinding finding, bool resolved) in Detail(report))
            {
                text.AppendLine(
                    $"#### {finding.RuleId} — {finding.Title} ({finding.Severity})");
                text.AppendLine();

                if (finding.LineNumber is not null)
                {
                    text.AppendLine($"Line {finding.LineNumber}.");
                    text.AppendLine();
                }

                text.AppendLine(finding.Description);
                text.AppendLine();
                text.AppendLine($"**Recommended remediation.** {finding.Recommendation}");
                text.AppendLine();
                text.AppendLine($"**Status.** {(resolved ? "Resolved by the proposed patch." : "Still present after the proposed patch.")}");
                text.AppendLine();
            }
        }

        text.AppendLine("## Unified diff");
        text.AppendLine("```diff");
        foreach (string line in report.UnifiedDiff) text.AppendLine(line);
        text.AppendLine("```");
        return text.ToString();
    }

    public static string Html(RemediationReport report)
    {
        string rows = string.Join("", Detail(report).Select(item =>
            $"<tr class=\"severity-{Encode(item.Finding.Severity.ToString().ToLowerInvariant())}\">" +
            $"<td><code>{Encode(item.Finding.RuleId)}</code></td>" +
            $"<td>{Encode(item.Finding.Severity.ToString())}</td>" +
            $"<td>{(item.Finding.LineNumber?.ToString() ?? "&mdash;")}</td>" +
            $"<td>{(item.Resolved ? "Resolved" : "Still present")}</td>" +
            $"<td><strong>{Encode(item.Finding.Title)}</strong>" +
            $"<p>{Encode(item.Finding.Description)}</p>" +
            $"<p class=\"recommendation\">{Encode(item.Finding.Recommendation)}</p></td>" +
            "</tr>"));

        string body = report.OriginalAnalysis.FindingCount == 0
            ? "<p>No configured rule violations were detected.</p>"
            : "<table><thead><tr><th>Rule</th><th>Severity</th><th>Line</th>" +
              $"<th>Status</th><th>Finding</th></tr></thead><tbody>{rows}</tbody></table>";

        string diff = Encode(string.Join("\n", report.UnifiedDiff));

        return "<!doctype html><html><head><meta charset=\"utf-8\">" +
            "<title>Remediation report</title><style>" +
            "body{font-family:system-ui;max-width:1000px;margin:40px auto;padding:0 24px}" +
            "pre{background:#0d1117;color:#e6edf3;padding:20px;overflow:auto}" +
            ".metric{display:inline-block;margin-right:24px}" +
            "table{border-collapse:collapse;width:100%}" +
            "th,td{border:1px solid #d0d7de;padding:8px;text-align:left;vertical-align:top}" +
            "th{background:#f6f8fa}" +
            ".severity-critical td:nth-child(2){color:#b3001b;font-weight:700}" +
            ".severity-high td:nth-child(2){color:#bc4c00;font-weight:700}" +
            ".recommendation{color:#0a3069}" +
            "</style></head><body>" +
            "<h1>DevSecOps Sentinel Remediation Report</h1>" +
            $"<h2>{Encode(report.FileName)}</h2>" +
            $"<p class=\"metric\"><strong>{report.OriginalAnalysis.FindingCount}</strong> findings before</p>" +
            $"<p class=\"metric\"><strong>{report.ProposedAnalysis.FindingCount}</strong> findings after</p>" +
            $"<p class=\"metric\"><strong>{report.RiskReductionPercent}%</strong> risk reduction</p>" +
            $"<h2>Findings</h2>{body}" +
            $"<h2>Unified diff</h2><pre>{diff}</pre></body></html>";
    }

    /// <summary>
    /// SARIF 2.1.0. The <c>level</c> property is a closed enum in the
    /// specification — none, note, warning or error — so severity names cannot be
    /// emitted directly. The original severity travels as
    /// <c>security-severity</c> on the rule, which is what GitHub code scanning
    /// reads, and the schema key must be <c>$schema</c>.
    /// </summary>
    public static SarifLog Sarif(RemediationReport report)
    {
        SarifRule[] rules = report.OriginalAnalysis.Findings
            .GroupBy(finding => finding.RuleId, StringComparer.Ordinal)
            .OrderBy(group => group.Key, StringComparer.Ordinal)
            .Select(group => new SarifRule(
                group.Key,
                group.First().Title,
                new SarifText(group.First().Title),
                new SarifText(group.First().Recommendation),
                new SarifConfiguration(LevelOf(group.First().Severity)),
                new SarifRuleProperties(
                    SecuritySeverityOf(group.First().Severity),
                    ["security", group.First().Severity.ToString().ToLowerInvariant()])))
            .ToArray();

        Dictionary<string, int> ruleIndex = rules
            .Select((rule, index) => (rule.Id, index))
            .ToDictionary(item => item.Id, item => item.index, StringComparer.Ordinal);

        SarifResult[] results = report.OriginalAnalysis.Findings
            .Select(finding => new SarifResult(
                finding.RuleId,
                ruleIndex.TryGetValue(finding.RuleId, out int index) ? index : 0,
                LevelOf(finding.Severity),
                new SarifText(finding.Description),
                finding.LineNumber is null
                    ? []
                    :
                    [
                        new SarifLocation(
                            new SarifPhysicalLocation(
                                new SarifArtifactLocation(report.FileName),
                                new SarifRegion(finding.LineNumber.Value)))
                    ]))
            .ToArray();

        return new SarifLog(
            "https://json.schemastore.org/sarif-2.1.0.json",
            "2.1.0",
            [new SarifRun(new SarifTool(new SarifDriver(
                ProductInfo.Name,
                ProductInfo.Version,
                "https://github.com/bgard68/DevSecOpsSentinel",
                rules)), results)]);
    }

    private static string LevelOf(WorkflowSeverity severity) => severity switch
    {
        WorkflowSeverity.Critical => "error",
        WorkflowSeverity.High => "error",
        WorkflowSeverity.Medium => "warning",
        _ => "note"
    };

    // GitHub code scanning buckets these as critical >= 9.0, high >= 7.0,
    // medium >= 4.0, low > 0.0.
    private static string SecuritySeverityOf(WorkflowSeverity severity) => severity switch
    {
        WorkflowSeverity.Critical => "9.5",
        WorkflowSeverity.High => "8.0",
        WorkflowSeverity.Medium => "5.0",
        _ => "3.0"
    };

    // Severity names, not their integer values: the JSON export is consumed by
    // people and by tools that key on the name, matching the SARIF export.
    public static string Json(RemediationReport report) => JsonSerializer.Serialize(
        report,
        new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() }
        });

    private static string Encode(string value) => System.Net.WebUtility.HtmlEncode(value);
}

// SARIF property names are fixed by the specification, so they are stated
// explicitly rather than left to the serializer's naming policy.
internal sealed record SarifLog(
    [property: JsonPropertyName("$schema")] string Schema,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("runs")] IReadOnlyList<SarifRun> Runs);

internal sealed record SarifRun(
    [property: JsonPropertyName("tool")] SarifTool Tool,
    [property: JsonPropertyName("results")] IReadOnlyList<SarifResult> Results);

internal sealed record SarifTool(
    [property: JsonPropertyName("driver")] SarifDriver Driver);

internal sealed record SarifDriver(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("informationUri")] string InformationUri,
    [property: JsonPropertyName("rules")] IReadOnlyList<SarifRule> Rules);

internal sealed record SarifRule(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("shortDescription")] SarifText ShortDescription,
    [property: JsonPropertyName("help")] SarifText Help,
    [property: JsonPropertyName("defaultConfiguration")] SarifConfiguration DefaultConfiguration,
    [property: JsonPropertyName("properties")] SarifRuleProperties Properties);

internal sealed record SarifRuleProperties(
    [property: JsonPropertyName("security-severity")] string SecuritySeverity,
    [property: JsonPropertyName("tags")] IReadOnlyList<string> Tags);

internal sealed record SarifConfiguration(
    [property: JsonPropertyName("level")] string Level);

internal sealed record SarifResult(
    [property: JsonPropertyName("ruleId")] string RuleId,
    [property: JsonPropertyName("ruleIndex")] int RuleIndex,
    [property: JsonPropertyName("level")] string Level,
    [property: JsonPropertyName("message")] SarifText Message,
    [property: JsonPropertyName("locations")] IReadOnlyList<SarifLocation> Locations);

internal sealed record SarifLocation(
    [property: JsonPropertyName("physicalLocation")] SarifPhysicalLocation PhysicalLocation);

internal sealed record SarifPhysicalLocation(
    [property: JsonPropertyName("artifactLocation")] SarifArtifactLocation ArtifactLocation,
    [property: JsonPropertyName("region")] SarifRegion Region);

internal sealed record SarifArtifactLocation(
    [property: JsonPropertyName("uri")] string Uri);

internal sealed record SarifRegion(
    [property: JsonPropertyName("startLine")] int StartLine);

internal sealed record SarifText(
    [property: JsonPropertyName("text")] string Text);
