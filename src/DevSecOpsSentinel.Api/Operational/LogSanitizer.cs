using System.Text;

namespace DevSecOpsSentinel.Api.Operational;

/// <summary>
/// Makes a request-supplied value safe to write to a log.
///
/// A request path is chosen by the caller. Written verbatim, a path containing
/// a carriage return or line feed splits one log entry into several, so an
/// attacker can fabricate entries that look as though the application emitted
/// them — a failed login that never happened, a success that did. Structured
/// logging does not prevent this on its own, because most sinks render the
/// message template into a single line of text.
///
/// Control characters are replaced rather than removed, so that a request which
/// attempted the injection is still visible as having done so.
/// </summary>
internal static class LogSanitizer
{
    /// <summary>
    /// Long enough for any legitimate path, short enough that a very long one
    /// cannot flood the log.
    /// </summary>
    private const int MaximumLength = 512;

    private const string Ellipsis = "…";

    public static string ForLog(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        StringBuilder sanitized = new(Math.Min(value.Length, MaximumLength) + 1);

        foreach (char character in value)
        {
            if (sanitized.Length >= MaximumLength)
            {
                sanitized.Append(Ellipsis);
                break;
            }

            sanitized.Append(
                char.IsControl(character) ? '�' : character);
        }

        return sanitized.ToString();
    }
}
