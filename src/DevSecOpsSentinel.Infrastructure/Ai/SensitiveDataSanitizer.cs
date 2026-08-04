using System.Text.RegularExpressions;
using DevSecOpsSentinel.Application;

namespace DevSecOpsSentinel.Infrastructure.Ai;

public sealed partial class SensitiveDataSanitizer :
    ISensitiveDataSanitizer
{
    public SanitizedWorkflow Sanitize(string content)
    {
        ArgumentNullException.ThrowIfNull(content);

        string sanitized = PrivateKeyRegex().Replace(
            content,
            "[REDACTED PRIVATE KEY]");

        sanitized = KnownTokenRegex().Replace(
            sanitized,
            "[REDACTED TOKEN]");

        sanitized = BearerTokenRegex().Replace(
            sanitized,
            match =>
                $"{match.Groups["prefix"].Value}[REDACTED]");

        sanitized = CommandArgumentRegex().Replace(
            sanitized,
            match =>
                $"{match.Groups["prefix"].Value}[REDACTED]");

        sanitized = ShellAssignmentRegex().Replace(
            sanitized,
            match =>
                $"{match.Groups["prefix"].Value}[REDACTED]");

        sanitized = MappingAssignmentRegex().Replace(
            sanitized,
            match =>
                $"{match.Groups["prefix"].Value}[REDACTED]");

        return new SanitizedWorkflow(
            sanitized,
            !string.Equals(
                content,
                sanitized,
                StringComparison.Ordinal));
    }

    [GeneratedRegex(
        "-----BEGIN [^-\\r\\n]*PRIVATE KEY-----[\\s\\S]*?-----END [^-\\r\\n]*PRIVATE KEY-----",
        RegexOptions.IgnoreCase)]
    private static partial Regex PrivateKeyRegex();

    [GeneratedRegex(
        "(?i)(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")]
    private static partial Regex KnownTokenRegex();

    [GeneratedRegex(
        "(?i)(?<prefix>Bearer\\s+)[A-Za-z0-9._~+/=-]{8,}")]
    private static partial Regex BearerTokenRegex();

    [GeneratedRegex(
        "(?i)(?<prefix>--(?:password|secret|token|api[_-]?key|authorization|connection[_-]?string)(?:=|\\s+))[\"']?[^\\s\"']+[\"']?")]
    private static partial Regex CommandArgumentRegex();

    [GeneratedRegex(
        "(?im)(?<prefix>\\b(?:PASSWORD|SECRET|TOKEN|API_KEY|APIKEY|AUTHORIZATION|CONNECTION_STRING)\\s*=\\s*)[\"']?[^\\s\\r\\n\"']+[\"']?")]
    private static partial Regex ShellAssignmentRegex();

    [GeneratedRegex(
        "(?im)(?<prefix>(?:^|[,{]\\s*)(?:[\"']?)(?:password|secret|token|api[_-]?key|authorization|connection[_-]?string)(?:[\"']?)\\s*:\\s*)[\"']?[^,}\\]\\r\\n]+[\"']?")]
    private static partial Regex MappingAssignmentRegex();
}
