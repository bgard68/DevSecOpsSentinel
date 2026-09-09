using DevSecOpsSentinel.Infrastructure.Ai;

namespace DevSecOpsSentinel.Infrastructure.Tests;

public sealed class AiSecurityTests
{
    private readonly SensitiveDataSanitizer _sanitizer = new();

    [Fact]
    public void Sanitize_CommonSecretPatterns_RedactsThem()
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
    public void Sanitize_InlineFlowMappingValues_RedactsThem()
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
    public void Sanitize_CommandLineSecretArguments_RedactsThem()
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
    public void Sanitize_ShellAssignmentsAndKnownTokens_RedactsThem()
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
    public void Sanitize_PrivateKeyBlock_RedactsIt()
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
    public void Sanitize_UnrelatedConfiguration_LeavesItUnchanged()
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
