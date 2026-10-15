using System.Text;
using System.Text.Json;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Api;

/// <summary>
/// One export format: what it is called, what it renders to, and how it is served.
///
/// The endpoint used to carry this as a switch over the route's format segment, which put
/// three separate things in one place — the accepted spellings, the media type and
/// file-naming convention of each, and the list of formats quoted back to a caller who asks
/// for one that does not exist. That last list was written by hand, so "sarif" could become
/// accepted and still be absent from the message naming what is accepted, or the reverse.
///
/// The formats are now data. The endpoint resolves one and serves it without knowing which
/// exist, and the supported-format message is derived from the same registry that answers
/// the request, so the two cannot disagree.
/// </summary>
internal interface IRemediationExporter
{
    /// <summary>The canonical name, as it appears in the supported-format message.</summary>
    string Format { get; }

    /// <summary>
    /// Other accepted spellings. <c>md</c> and <c>patch</c> are what people type; they are
    /// aliases rather than formats so they do not clutter the message.
    /// </summary>
    IReadOnlyList<string> Aliases => [];

    RemediationExportResponse Render(RemediationReport report, string baseName);
}

/// <summary>
/// A rendered export. <paramref name="DownloadName"/> is null for a format served inline —
/// SARIF is consumed by tools reading the response body, not saved by a person.
/// </summary>
internal sealed record RemediationExportResponse(
    byte[] Content,
    string ContentType,
    string? DownloadName);

internal static class RemediationExporters
{
    /// <summary>
    /// Registration order is the order the supported-format message lists them.
    /// </summary>
    private static readonly IReadOnlyList<IRemediationExporter> Registered =
    [
        new MarkdownExporter(),
        new HtmlExporter(),
        new SarifExporter(),
        new JsonExporter(),
        new DiffExporter()
    ];

    public static string SupportedFormats =>
        string.Join(", ", Registered.Select(exporter => exporter.Format));

    /// <summary>
    /// The exporter a caller asked for, or null. Case-insensitive, matching the route
    /// segment's previous <c>ToLowerInvariant</c> treatment.
    /// </summary>
    public static IRemediationExporter? For(string format) =>
        Registered.FirstOrDefault(exporter =>
            exporter.Format.Equals(format, StringComparison.OrdinalIgnoreCase) ||
            exporter.Aliases.Contains(format, StringComparer.OrdinalIgnoreCase));

    private static byte[] Utf8(string value) => Encoding.UTF8.GetBytes(value);

    private sealed class MarkdownExporter : IRemediationExporter
    {
        public string Format => "markdown";
        public IReadOnlyList<string> Aliases => ["md"];

        public RemediationExportResponse Render(RemediationReport report, string baseName) =>
            new(
                Utf8(RemediationExports.Markdown(report)),
                "text/markdown",
                $"{baseName}-remediation.md");
    }

    private sealed class HtmlExporter : IRemediationExporter
    {
        public string Format => "html";

        public RemediationExportResponse Render(RemediationReport report, string baseName) =>
            new(
                Utf8(RemediationExports.Html(report)),
                "text/html",
                $"{baseName}-remediation.html");
    }

    private sealed class SarifExporter : IRemediationExporter
    {
        public string Format => "sarif";

        /// <summary>
        /// Serialised here rather than handed to the framework, so the media type and the
        /// bytes are decided in the same place as every other format. Every SARIF property
        /// name is fixed by an attribute, so the naming policy does not reach this document.
        /// </summary>
        public RemediationExportResponse Render(RemediationReport report, string baseName) =>
            new(
                Utf8(JsonSerializer.Serialize(
                    RemediationExports.Sarif(report),
                    new JsonSerializerOptions(JsonSerializerDefaults.Web))),
                "application/sarif+json",
                DownloadName: null);
    }

    private sealed class JsonExporter : IRemediationExporter
    {
        public string Format => "json";

        public RemediationExportResponse Render(RemediationReport report, string baseName) =>
            new(
                Utf8(RemediationExports.Json(report)),
                "application/json",
                $"{baseName}-remediation.json");
    }

    private sealed class DiffExporter : IRemediationExporter
    {
        public string Format => "diff";
        public IReadOnlyList<string> Aliases => ["patch"];

        public RemediationExportResponse Render(RemediationReport report, string baseName) =>
            new(
                Utf8(string.Join("\n", report.UnifiedDiff)),
                "text/x-diff",
                $"{baseName}.patch");
    }
}
