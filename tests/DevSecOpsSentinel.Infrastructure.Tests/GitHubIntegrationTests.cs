using System.Security.Cryptography;
using System.Text.Json;
using DevSecOpsSentinel.Infrastructure.GitHub;

namespace DevSecOpsSentinel.Infrastructure.Tests;

public sealed class GitHubIntegrationTests
{
    [Fact]
    public void Jwt_factory_creates_rs256_token_with_expected_issuer()
    {
        string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string keyPath = Path.Combine(directory, "github-app.pem");

        try
        {
            using RSA rsa = RSA.Create(2048);
            File.WriteAllText(keyPath, rsa.ExportRSAPrivateKeyPem());
            var options = new GitHubOptions
            {
                Enabled = true,
                AppId = 12345,
                InstallationId = 67890,
                PrivateKeyPath = keyPath,
                AllowedRepositories = ["bgard68/DevSecOpsSentinel-Sandbox"]
            };

            string token = new GitHubAppJwtFactory(options)
                .CreateToken(DateTimeOffset.FromUnixTimeSeconds(1_800_000_000));

            string[] parts = token.Split('.');
            Assert.Equal(3, parts.Length);

            using JsonDocument header = JsonDocument.Parse(Decode(parts[0]));
            using JsonDocument payload = JsonDocument.Parse(Decode(parts[1]));
            Assert.Equal("RS256", header.RootElement.GetProperty("alg").GetString());
            Assert.Equal("12345", payload.RootElement.GetProperty("iss").GetString());
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Theory]
    [InlineData("bgard68", "DevSecOpsSentinel-Sandbox", true)]
    [InlineData("BGARD68", "devsecopssentinel-sandbox", true)]
    [InlineData("bgard68", "ToDoApp", false)]
    public void Allowlist_is_case_insensitive_and_restrictive(
        string owner,
        string repository,
        bool expected)
    {
        var options = new GitHubOptions
        {
            AllowedRepositories = ["bgard68/DevSecOpsSentinel-Sandbox"]
        };

        Assert.Equal(expected, options.IsAllowed(owner, repository));
    }

    private static byte[] Decode(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        return Convert.FromBase64String(padded);
    }
}
