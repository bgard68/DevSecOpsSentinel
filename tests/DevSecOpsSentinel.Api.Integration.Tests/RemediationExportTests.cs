using System.Text.Json;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Api.Integration.Tests;

/// <summary>
/// Functional tests for the four export renderers, driven from a hand-built
/// report so that every severity, a null line number and a shorter change list
/// than finding list are all reachable. Analysing a real workflow cannot produce
/// those combinations on demand, and the branches that handle them are the ones
/// that turn an export into evidence someone can act on.
///
/// The escaping test uses a payload that genuinely contains markup. An assertion
/// that looks for a script tag in a document that never had one passes whether
/// or not the encoder is called at all.
/// </summary>
public sealed class RemediationExportTests
{
    private static WorkflowFinding Finding(
        string ruleId,
        WorkflowSeverity severity,
        int? line,
        string title = "Title",
        string description = "Description",
        string recommendation = "Recommendation") =>
        new(ruleId, severity, title, description, line, recommendation, true);

    private static RemediationReport Report(
        IReadOnlyList<WorkflowFinding> original,
        IReadOnlyList<bool>? resolved = null,
        IReadOnlyList<WorkflowFinding>? remaining = null,
        string fileName = "build.yml",
        IReadOnlyList<string>? diff = null)
    {
        IReadOnlyList<bool> flags = resolved ?? [.. original.Select(_ => false)];

        RemediationChange[] changes = [.. original
            .Select((finding, index) => new RemediationChange(
                finding.RuleId,
                finding.Title,
                finding.Severity,
                flags[index],
                finding.Recommendation))];

        return new RemediationReport(
            fileName,
            new WorkflowAnalysisResult(fileName, true, [], original, null),
            new WorkflowAnalysisResult(fileName, true, [], remaining ?? [], null),
            changes,
            diff ?? ["--- a/build.yml", "+++ b/build.yml"],
            OriginalRiskScore: 10,
            ProposedRiskScore: 2,
            RiskReductionPercent: 80,
            PatchValid: true);
    }

    // ------------------------------------------------------------- Markdown

    [Fact]
    public void Markdown_FindingResolvedByThePatch_RendersTheRowWithItsSeverityLineAndStatus()
    {
        // Arrange
        RemediationReport report = Report(
            [Finding("GHA002", WorkflowSeverity.High, 4, "Excessive permissions")],
            resolved: [true]);

        // Act
        string markdown = RemediationExports.Markdown(report);

        // Assert
        Assert.Contains(
            "| GHA002 | High | 4 | Resolved | Excessive permissions |",
            markdown,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Markdown_FindingSurvivesThePatch_RendersStillPresentRatherThanResolved()
    {
        // Arrange
        RemediationReport report = Report(
            [Finding("GHA010", WorkflowSeverity.Medium, 12, "Self-hosted runner")],
            resolved: [false]);

        // Act
        string markdown = RemediationExports.Markdown(report);

        // Assert
        Assert.Contains(
            "| GHA010 | Medium | 12 | Still present | Self-hosted runner |",
            markdown,
            StringComparison.Ordinal);
        Assert.DoesNotContain("Resolved by the proposed patch.", markdown, StringComparison.Ordinal);
    }

    [Fact]
    public void Markdown_FindingHasNoLineNumber_RendersAnEmDashInsteadOfAZero()
    {
        // Arrange. A whole-workflow finding has no line. Rendering 0 would send
        // a reader to the top of the file looking for something that is not there.
        RemediationReport report = Report(
            [Finding("GHA009", WorkflowSeverity.Low, null, "Undeclared permissions")]);

        // Act
        string markdown = RemediationExports.Markdown(report);

        // Assert
        Assert.Contains(
            "| GHA009 | Low | — | Still present | Undeclared permissions |",
            markdown,
            StringComparison.Ordinal);
        Assert.DoesNotContain("| GHA009 | Low | 0 |", markdown, StringComparison.Ordinal);
    }

    [Fact]
    public void Markdown_ReportHasNoFindings_StatesSoAndOmitsTheTableEntirely()
    {
        // Arrange
        RemediationReport report = Report([]);

        // Act
        string markdown = RemediationExports.Markdown(report);

        // Assert
        Assert.Contains(
            "No configured rule violations were detected.",
            markdown,
            StringComparison.Ordinal);
        Assert.DoesNotContain("| Rule | Severity |", markdown, StringComparison.Ordinal);
        Assert.DoesNotContain("### Detail", markdown, StringComparison.Ordinal);
    }

    [Fact]
    public void Markdown_ChangeListIsShorterThanTheFindingList_ReportsTheExtraFindingAsUnresolved()
    {
        // Arrange. Detail() pairs findings to changes by index and guards the
        // upper bound. If the two ever drift apart, the unmatched finding has to
        // read as still present: claiming a fix that was never applied is the
        // one failure mode this export cannot have.
        WorkflowFinding matched = Finding("GHA002", WorkflowSeverity.High, 4, "Matched");
        WorkflowFinding unmatched = Finding("GHA003", WorkflowSeverity.Medium, 7, "Unmatched");

        RemediationReport truncated = Report([matched], resolved: [true]) with
        {
            OriginalAnalysis = new WorkflowAnalysisResult(
                "build.yml", true, [], [matched, unmatched], null)
        };

        // Act
        string markdown = RemediationExports.Markdown(truncated);

        // Assert
        Assert.Contains(
            "| GHA002 | High | 4 | Resolved | Matched |",
            markdown,
            StringComparison.Ordinal);
        Assert.Contains(
            "| GHA003 | Medium | 7 | Still present | Unmatched |",
            markdown,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Markdown_ReportHasADiff_WrapsItInAFencedDiffBlock()
    {
        // Arrange
        RemediationReport report = Report(
            [Finding("GHA002", WorkflowSeverity.High, 4)],
            diff: ["@@ -1,3 +1,3 @@", "-permissions: write-all", "+permissions: read-all"]);

        // Act
        string markdown = RemediationExports.Markdown(report);

        // Assert
        Assert.Contains("```diff", markdown, StringComparison.Ordinal);
        Assert.Contains("-permissions: write-all", markdown, StringComparison.Ordinal);
        Assert.Contains("+permissions: read-all", markdown, StringComparison.Ordinal);
    }

    // ----------------------------------------------------------------- HTML

    [Fact]
    public void Html_FindingTextContainsMarkup_EncodesItRatherThanEmittingLiveTags()
    {
        // Arrange. Finding text is built from workflow content, which an
        // untrusted contributor controls. This report is opened in a browser.
        RemediationReport report = Report(
            [
                Finding(
                    "GHA005",
                    WorkflowSeverity.Critical,
                    9,
                    title: "<script>alert('title')</script>",
                    description: "<img src=x onerror=alert(1)>",
                    recommendation: "Quote \"the\" & escape <it>")
            ]);

        // Act
        string html = RemediationExports.Html(report);

        // Assert
        Assert.DoesNotContain("<script>", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<img src=x", html, StringComparison.OrdinalIgnoreCase);

        Assert.Contains(
            "&lt;script&gt;alert(&#39;title&#39;)&lt;/script&gt;",
            html,
            StringComparison.Ordinal);
        Assert.Contains(
            "&lt;img src=x onerror=alert(1)&gt;",
            html,
            StringComparison.Ordinal);
        Assert.Contains(
            "Quote &quot;the&quot; &amp; escape &lt;it&gt;",
            html,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Html_FileNameContainsMarkup_EncodesTheHeadingToo()
    {
        // Arrange. The file name reaches the document heading unfiltered by the
        // endpoint, so it is an injection point in its own right.
        RemediationReport report = Report(
            [Finding("GHA002", WorkflowSeverity.High, 4)],
            fileName: "<script>alert(2)</script>.yml");

        // Act
        string html = RemediationExports.Html(report);

        // Assert
        Assert.Contains(
            "<h2>&lt;script&gt;alert(2)&lt;/script&gt;.yml</h2>",
            html,
            StringComparison.Ordinal);
        Assert.DoesNotContain("<script>alert(2)", html, StringComparison.Ordinal);
    }

    [Fact]
    public void Html_DiffContainsMarkup_EncodesItInsideThePreBlock()
    {
        // Arrange
        RemediationReport report = Report(
            [Finding("GHA002", WorkflowSeverity.High, 4)],
            diff: ["+        run: echo <script>alert(3)</script>"]);

        // Act
        string html = RemediationExports.Html(report);

        // Assert
        Assert.Contains(
            "&lt;script&gt;alert(3)&lt;/script&gt;",
            html,
            StringComparison.Ordinal);
        Assert.DoesNotContain("<script>alert(3)", html, StringComparison.Ordinal);
    }

    [Fact]
    public void Html_CriticalFinding_TagsTheRowWithItsLowerCaseSeverityClass()
    {
        // Arrange. The stylesheet colours the severity cell by this class, so a
        // casing change silently drops the visual severity signal.
        RemediationReport report = Report(
            [Finding("GHA007", WorkflowSeverity.Critical, 9, "Untrusted checkout")],
            resolved: [true]);

        // Act
        string html = RemediationExports.Html(report);

        // Assert
        Assert.Contains("<tr class=\"severity-critical\">", html, StringComparison.Ordinal);
        Assert.Contains("<td><code>GHA007</code></td>", html, StringComparison.Ordinal);
        Assert.Contains("<td>Critical</td>", html, StringComparison.Ordinal);
        Assert.Contains("<td>9</td>", html, StringComparison.Ordinal);
        Assert.Contains("<td>Resolved</td>", html, StringComparison.Ordinal);
    }

    [Fact]
    public void Html_FindingHasNoLineNumber_RendersTheMdashEntityInTheLineCell()
    {
        // Arrange
        RemediationReport report = Report(
            [Finding("GHA009", WorkflowSeverity.Low, null)]);

        // Act
        string html = RemediationExports.Html(report);

        // Assert
        Assert.Contains("<td>&mdash;</td>", html, StringComparison.Ordinal);
    }

    [Fact]
    public void Html_ReportHasNoFindings_ReplacesTheTableWithAStatement()
    {
        // Arrange
        RemediationReport report = Report([]);

        // Act
        string html = RemediationExports.Html(report);

        // Assert
        Assert.Contains(
            "<p>No configured rule violations were detected.</p>",
            html,
            StringComparison.Ordinal);
        Assert.DoesNotContain("<tbody>", html, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------- SARIF

    [Theory]
    [InlineData(WorkflowSeverity.Critical, "error", "9.5")]
    [InlineData(WorkflowSeverity.High, "error", "8.0")]
    [InlineData(WorkflowSeverity.Medium, "warning", "5.0")]
    [InlineData(WorkflowSeverity.Low, "note", "3.0")]
    public void Sarif_EachSeverity_MapsToItsClosedEnumLevelAndSecuritySeverityBucket(
        WorkflowSeverity severity,
        string expectedLevel,
        string expectedSecuritySeverity)
    {
        // Arrange. `level` is a closed enum in SARIF, so severity names cannot
        // be emitted there. The original severity survives as security-severity,
        // which is the number GitHub code scanning buckets on.
        RemediationReport report = Report([Finding("GHA001", severity, 3)]);

        // Act
        SarifLog log = RemediationExports.Sarif(report);

        // Assert
        SarifRule rule = Assert.Single(log.Runs[0].Tool.Driver.Rules);
        SarifResult result = Assert.Single(log.Runs[0].Results);

        Assert.Equal(expectedLevel, rule.DefaultConfiguration.Level);
        Assert.Equal(expectedSecuritySeverity, rule.Properties.SecuritySeverity);
        Assert.Equal(expectedLevel, result.Level);
        Assert.Equal(["security", severity.ToString().ToLowerInvariant()], rule.Properties.Tags);
    }

    [Fact]
    public void Sarif_SeveralFindingsShareARuleId_EmitsTheRuleOnceAndPointsEveryResultAtIt()
    {
        // Arrange. SARIF consumers reject a driver that declares the same rule
        // twice, and ruleIndex has to address the deduplicated array.
        RemediationReport report = Report(
            [
                Finding("GHA003", WorkflowSeverity.Medium, 5),
                Finding("GHA001", WorkflowSeverity.High, 9),
                Finding("GHA003", WorkflowSeverity.Medium, 14)
            ]);

        // Act
        SarifLog log = RemediationExports.Sarif(report);

        // Assert
        SarifRun run = Assert.Single(log.Runs);

        Assert.Equal(
            ["GHA001", "GHA003"],
            run.Tool.Driver.Rules.Select(rule => rule.Id));

        Assert.Equal(
            ["GHA003", "GHA001", "GHA003"],
            run.Results.Select(result => result.RuleId));

        Assert.Equal([1, 0, 1], run.Results.Select(result => result.RuleIndex));
    }

    [Fact]
    public void Sarif_FindingCarriesALineNumber_EmitsOneLocationNamingTheWorkflowFile()
    {
        // Arrange
        RemediationReport report = Report(
            [Finding("GHA005", WorkflowSeverity.Critical, 17)],
            fileName: "release.yml");

        // Act
        SarifLog log = RemediationExports.Sarif(report);

        // Assert
        SarifResult result = Assert.Single(log.Runs[0].Results);
        SarifLocation location = Assert.Single(result.Locations);

        Assert.Equal("release.yml", location.PhysicalLocation.ArtifactLocation.Uri);
        Assert.Equal(17, location.PhysicalLocation.Region.StartLine);
    }

    [Fact]
    public void Sarif_FindingHasNoLineNumber_EmitsAnEmptyLocationListRatherThanLineZero()
    {
        // Arrange. SARIF startLine is 1-based, so a synthesised 0 is invalid and
        // GitHub rejects the upload rather than ignoring the region.
        RemediationReport report = Report(
            [Finding("GHA009", WorkflowSeverity.Low, null)]);

        // Act
        SarifLog log = RemediationExports.Sarif(report);

        // Assert
        Assert.Empty(Assert.Single(log.Runs[0].Results).Locations);
    }

    [Fact]
    public void Sarif_AnyReport_DescribesTheToolFromTheAssemblyRatherThanALiteral()
    {
        // Arrange. The version was previously repeated as a literal in five
        // places and had drifted to three different values. ProductInfo is now
        // the single source; asserting equality against it is what stops a
        // hardcoded string reappearing here.
        RemediationReport report = Report([Finding("GHA001", WorkflowSeverity.High, 3)]);

        // Act
        SarifDriver driver = RemediationExports.Sarif(report).Runs[0].Tool.Driver;

        // Assert
        Assert.Equal(ProductInfo.Name, driver.Name);
        Assert.Equal(ProductInfo.Version, driver.Version);
        Assert.Equal("https://github.com/bgard68/DevSecOpsSentinel", driver.InformationUri);
    }

    [Fact]
    public void Sarif_AnyReport_DeclaresTheSchemaKeyAndVersionTheSpecificationRequires()
    {
        // Arrange
        RemediationReport report = Report([Finding("GHA001", WorkflowSeverity.High, 3)]);

        // Act
        SarifLog log = RemediationExports.Sarif(report);

        // Assert
        Assert.Equal("https://json.schemastore.org/sarif-2.1.0.json", log.Schema);
        Assert.Equal("2.1.0", log.Version);
    }

    [Fact]
    public void Sarif_ReportHasNoFindings_EmitsARunWithNoRulesAndNoResults()
    {
        // Arrange. A clean scan still has to produce a well-formed log, or an
        // upload step fails on every workflow that passes.
        RemediationReport report = Report([]);

        // Act
        SarifLog log = RemediationExports.Sarif(report);

        // Assert
        SarifRun run = Assert.Single(log.Runs);
        Assert.Empty(run.Tool.Driver.Rules);
        Assert.Empty(run.Results);
        Assert.Equal("2.1.0", log.Version);
    }

    [Fact]
    public void Sarif_ResultMessage_CarriesTheFindingDescriptionNotItsTitle()
    {
        // Arrange. The message is what a reviewer reads on the annotation; the
        // title alone repeats the rule name and explains nothing.
        RemediationReport report = Report(
            [
                Finding(
                    "GHA006",
                    WorkflowSeverity.High,
                    11,
                    title: "Persisted credentials",
                    description: "The checkout step leaves the token on disk.")
            ]);

        // Act
        SarifLog log = RemediationExports.Sarif(report);

        // Assert
        Assert.Equal(
            "The checkout step leaves the token on disk.",
            Assert.Single(log.Runs[0].Results).Message.Text);
    }

    // ----------------------------------------------------------------- JSON

    [Fact]
    public void Json_ReportWithFindings_WritesSeverityAsItsNameNotItsIntegerValue()
    {
        // Arrange. The client filters and sorts by comparing this field to
        // severity names. An integer renders an empty list and a "Low" label on
        // a workflow that holds critical findings.
        RemediationReport report = Report(
            [Finding("GHA007", WorkflowSeverity.Critical, 9)]);

        // Act
        string json = RemediationExports.Json(report);

        // Assert
        using JsonDocument document = JsonDocument.Parse(json);

        JsonElement finding = document.RootElement
            .GetProperty("originalAnalysis")
            .GetProperty("findings")[0];

        Assert.Equal("Critical", finding.GetProperty("severity").GetString());
        Assert.Equal(JsonValueKind.String, finding.GetProperty("severity").ValueKind);
    }

    [Fact]
    public void Json_ReportWithFindings_PreservesTheScoresAndTheResolvedChangeFlags()
    {
        // Arrange
        RemediationReport report = Report(
            [
                Finding("GHA002", WorkflowSeverity.High, 4),
                Finding("GHA003", WorkflowSeverity.Medium, 7)
            ],
            resolved: [true, false]);

        // Act
        string json = RemediationExports.Json(report);

        // Assert
        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;

        Assert.Equal("build.yml", root.GetProperty("fileName").GetString());
        Assert.Equal(10, root.GetProperty("originalRiskScore").GetInt32());
        Assert.Equal(2, root.GetProperty("proposedRiskScore").GetInt32());
        Assert.Equal(80, root.GetProperty("riskReductionPercent").GetInt32());
        Assert.True(root.GetProperty("patchValid").GetBoolean());

        Assert.Equal(
            [true, false],
            root.GetProperty("changes")
                .EnumerateArray()
                .Select(change => change.GetProperty("resolved").GetBoolean()));
    }
}
