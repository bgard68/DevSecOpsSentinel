using System.Text.RegularExpressions;
using DevSecOpsSentinel.Application;

namespace DevSecOpsSentinel.Infrastructure.Ai;

public sealed partial class SensitiveDataSanitizer : ISensitiveDataSanitizer
{
    public SanitizedWorkflow Sanitize(string content)
    {
        string sanitized = PrivateKeyRegex().Replace(content, "[REDACTED PRIVATE KEY]");
        sanitized = SensitiveAssignmentRegex().Replace(
            sanitized,
            match => $"{match.Groups[1].Value}: [REDACTED]");
        sanitized = BearerTokenRegex().Replace(sanitized, "Bearer [REDACTED]");

        return new SanitizedWorkflow(sanitized, !string.Equals(content, sanitized, StringComparison.Ordinal));
    }

    [GeneratedRegex("-----BEGIN [^-]+ PRIVATE KEY-----[\\s\\S]*?-----END [^-]+ PRIVATE KEY-----", RegexOptions.IgnoreCase)]
    private static partial Regex PrivateKeyRegex();

    [GeneratedRegex("(?im)^([ \\t]*(?:password|secret|token|api[_-]?key|authorization|connection[_-]?string)[ \\t]*):[ \\t]*[^\\r\\n]+$")]
    private static partial Regex SensitiveAssignmentRegex();

    [GeneratedRegex("(?i)Bearer\\s+[A-Za-z0-9._~+/=-]+")]
    private static partial Regex BearerTokenRegex();
}
