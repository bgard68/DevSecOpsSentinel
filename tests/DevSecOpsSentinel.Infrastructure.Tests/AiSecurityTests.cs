using DevSecOpsSentinel.Infrastructure.Ai;

namespace DevSecOpsSentinel.Infrastructure.Tests;

public sealed class AiSecurityTests
{
    private readonly SensitiveDataSanitizer _sanitizer = new();

    [Fact]
    public void Sanitizer_redacts_common_secret_patterns()
    {
        const string source =
            "token: abc123\n" +
            "authorization: Bearer secret-value\n" +
            "api_key: key-value";

        var result = _sanitizer.Sanitize(source);

        Assert.True(result.WasRedacted);
        Assert.DoesNotContain("abc123", result.Content);
        Assert.DoesNotContain("secret-value", result.Content);
        Assert.DoesNotContain("key-value", result.Content);
    }

    [Fact]
    public void Sanitizer_redacts_inline_flow_mapping_values()
    {
        const string source =
            "env: { TOKEN: inline-secret, MODE: safe }";

        var result = _sanitizer.Sanitize(source);

        Assert.True(result.WasRedacted);
        Assert.DoesNotContain(
            "inline-secret",
            result.Content,
            StringComparison.Ordinal);
        Assert.Contains(
            "MODE: safe",
            result.Content,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Sanitizer_redacts_command_line_secret_arguments()
    {
        const string source =
            "run: deploy --token=command-secret --environment test";

        var result = _sanitizer.Sanitize(source);

        Assert.True(result.WasRedacted);
        Assert.DoesNotContain(
            "command-secret",
            result.Content,
            StringComparison.Ordinal);
        Assert.Contains(
            "--environment test",
            result.Content,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Sanitizer_redacts_shell_assignments_and_known_tokens()
    {
        string source =
            "TOKEN=shell-secret\n" +
            "value=" + "ghp_" + new string('A', 36);

        var result = _sanitizer.Sanitize(source);

        Assert.True(result.WasRedacted);
        Assert.DoesNotContain(
            "shell-secret",
            result.Content,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "ghp_",
            result.Content,
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Sanitizer_redacts_private_key_blocks()
    {
        string begin =
            "-----BEGIN " + "RSA PRIVATE KEY-----";
        string end =
            "-----END " + "RSA PRIVATE KEY-----";
        string source =
            $"{begin}\nnot-a-real-key\n{end}";

        var result = _sanitizer.Sanitize(source);

        Assert.True(result.WasRedacted);
        Assert.DoesNotContain(
            "not-a-real-key",
            result.Content,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Sanitizer_does_not_redact_unrelated_configuration()
    {
        const string source =
            "permissions: read-all\n" +
            "mode: write\n" +
            "timeout-minutes: 15";

        var result = _sanitizer.Sanitize(source);

        Assert.False(result.WasRedacted);
        Assert.Equal(source, result.Content);
    }
}
