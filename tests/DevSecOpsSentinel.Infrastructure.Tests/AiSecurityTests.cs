using DevSecOpsSentinel.Infrastructure.Ai;

namespace DevSecOpsSentinel.Infrastructure.Tests;

public sealed class AiSecurityTests
{
    [Fact]
    public void Sanitizer_redacts_common_secret_patterns()
    {
        const string source = "token: abc123\nauthorization: Bearer secret-value\napi_key: key-value";
        var sanitizer = new SensitiveDataSanitizer();

        var result = sanitizer.Sanitize(source);

        Assert.True(result.WasRedacted);
        Assert.DoesNotContain("abc123", result.Content);
        Assert.DoesNotContain("secret-value", result.Content);
        Assert.DoesNotContain("key-value", result.Content);
    }
}
