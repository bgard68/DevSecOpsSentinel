using System.Text;
using DevSecOpsSentinel.Application;

namespace DevSecOpsSentinel.Infrastructure.GitHub;

public sealed class GitHubPrivateKeySource(GitHubOptions options)
    : IGitHubPrivateKeySource
{
    private const string PemMarker = "-----BEGIN";

    // The key does not change while the process runs, and the JWT factory would
    // otherwise re-read the file on every token refresh.
    private string? _cachedPem;

    public bool IsAvailable =>
        !string.IsNullOrWhiteSpace(options.PrivateKey) ||
        (!string.IsNullOrWhiteSpace(options.PrivateKeyPath) &&
         File.Exists(options.PrivateKeyPath));

    public string Description =>
        !string.IsNullOrWhiteSpace(options.PrivateKey)
            ? "configuration"
            : !string.IsNullOrWhiteSpace(options.PrivateKeyPath)
                ? "file"
                : "none";

    public string ReadPem()
    {
        if (_cachedPem is not null)
        {
            return _cachedPem;
        }

        if (!string.IsNullOrWhiteSpace(options.PrivateKey))
        {
            _cachedPem = NormalisePem(options.PrivateKey);
            return _cachedPem;
        }

        if (string.IsNullOrWhiteSpace(options.PrivateKeyPath))
        {
            throw new InvalidOperationException(
                "No GitHub App private key is configured. Set GitHub:PrivateKey " +
                "to the key material, or GitHub:PrivateKeyPath to a readable file.");
        }

        if (!File.Exists(options.PrivateKeyPath))
        {
            throw new InvalidOperationException(
                "The configured GitHub App private key file is unavailable.");
        }

        _cachedPem = File.ReadAllText(options.PrivateKeyPath);
        return _cachedPem;
    }

    /// <summary>
    /// Accepts the PEM directly, or base64-encoded.
    ///
    /// A PEM is multi-line, and the tooling around environment variables and
    /// deployment settings handles line breaks inconsistently — a key pasted
    /// into a setting frequently arrives with them stripped or escaped, and
    /// fails to import for a reason that looks nothing like the cause. Encoding
    /// it removes the question.
    /// </summary>
    private static string NormalisePem(string configured)
    {
        string value = configured.Trim();

        if (value.Contains(PemMarker, StringComparison.Ordinal))
        {
            return value;
        }

        try
        {
            string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(value));

            if (decoded.Contains(PemMarker, StringComparison.Ordinal))
            {
                return decoded;
            }
        }
        catch (FormatException)
        {
            // Falls through to the error below, which says something useful.
        }

        throw new InvalidOperationException(
            "GitHub:PrivateKey is neither PEM text nor base64-encoded PEM. " +
            "Supply the key file's contents, or that content base64-encoded.");
    }
}
