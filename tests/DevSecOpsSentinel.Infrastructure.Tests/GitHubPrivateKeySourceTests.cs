using System.Security.Cryptography;
using System.Text;
using DevSecOpsSentinel.Infrastructure.GitHub;

namespace DevSecOpsSentinel.Infrastructure.Tests;

public sealed class GitHubPrivateKeySourceTests : IDisposable
{
    /// <summary>
    /// Generated per run rather than written into the file.
    ///
    /// A literal PEM in source is indistinguishable from a leaked key to a
    /// scanner, and the pre-commit hook correctly refuses one. Generating it also
    /// makes the test stronger: the value is a real key, so anything that parses
    /// it is doing so properly rather than matching a shape.
    /// </summary>
    private static string CreatePem()
    {
        using RSA rsa = RSA.Create(2048);
        return rsa.ExportRSAPrivateKeyPem() + "\n";
    }

    private readonly string _pem = CreatePem();

    private readonly string _keyPath = Path.Join(
        Path.GetTempPath(),
        $"sentinel-key-{Guid.NewGuid():N}.pem");

    public void Dispose()
    {
        if (File.Exists(_keyPath))
        {
            File.Delete(_keyPath);
        }
    }

    [Fact]
    public void Resolve_PemSuppliedAsConfiguration_IsUsedDirectly()
    {
        GitHubPrivateKeySource source = new(new GitHubOptions { PrivateKey = _pem });

        Assert.True(source.IsAvailable);
        Assert.Equal("configuration", source.Description);
        Assert.Equal(_pem.Trim(), source.ReadPem());
    }

    [Fact]
    public void Resolve_Base64EncodedPem_IsDecoded()
    {
        // Deployment settings and environment variables handle line breaks
        // inconsistently, so a key pasted into one frequently arrives mangled.
        // Encoding removes the question, and a Key Vault secret stores it so.
        string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(_pem));

        GitHubPrivateKeySource source = new(new GitHubOptions { PrivateKey = encoded });

        Assert.Equal(_pem, source.ReadPem());
    }

    [Fact]
    public void Resolve_ResolvedKey_ImportsAsAnRsaKey()
    {
        // The point of all of this is that something can sign with it.
        GitHubPrivateKeySource source = new(new GitHubOptions
        {
            PrivateKey = Convert.ToBase64String(Encoding.UTF8.GetBytes(_pem))
        });

        using RSA rsa = RSA.Create();
        rsa.ImportFromPem(source.ReadPem());

        Assert.Equal(2048, rsa.KeySize);
    }

    [Fact]
    public void Resolve_NoConfiguredKey_FallsBackToTheFilePath()
    {
        File.WriteAllText(_keyPath, _pem);

        GitHubPrivateKeySource source = new(new GitHubOptions { PrivateKeyPath = _keyPath });

        Assert.True(source.IsAvailable);
        Assert.Equal("file", source.Description);
        Assert.Equal(_pem, source.ReadPem());
    }

    [Fact]
    public void Resolve_BothConfiguredKeyAndFilePath_PrefersTheConfiguredKey()
    {
        // A stale key file left on a host must not serve a deployment that was
        // given its key through configuration.
        string stalePem = CreatePem();
        File.WriteAllText(_keyPath, stalePem);

        GitHubPrivateKeySource source = new(new GitHubOptions
        {
            PrivateKey = _pem,
            PrivateKeyPath = _keyPath
        });

        Assert.Equal("configuration", source.Description);
        Assert.Equal(_pem.Trim(), source.ReadPem());
        Assert.NotEqual(stalePem, source.ReadPem());
    }

    [Fact]
    public void Resolve_NoKeyAnywhere_IsReportedRatherThanGuessedAt()
    {
        GitHubPrivateKeySource source = new(new GitHubOptions());

        Assert.False(source.IsAvailable);
        Assert.Equal("none", source.Description);

        InvalidOperationException error =
            Assert.Throws<InvalidOperationException>(() => source.ReadPem());

        Assert.Contains("GitHub:PrivateKey", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Resolve_MissingFile_IsReportedAsUnavailable()
    {
        GitHubPrivateKeySource source = new(new GitHubOptions
        {
            PrivateKeyPath = Path.Join(Path.GetTempPath(), "does-not-exist.pem")
        });

        Assert.False(source.IsAvailable);
        Assert.Throws<InvalidOperationException>(() => source.ReadPem());
    }

    [Fact]
    public void Resolve_ValueThatIsNeitherPemNorBase64_ReportsWhyItIsUnusable()
    {
        GitHubPrivateKeySource source = new(new GitHubOptions
        {
            PrivateKey = "not a key"
        });

        InvalidOperationException error =
            Assert.Throws<InvalidOperationException>(() => source.ReadPem());

        Assert.Contains("base64", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Resolve_CalledTwice_ReadsTheKeyOnceAndReusesIt()
    {
        // The JWT factory previously re-read the file on every token refresh.
        File.WriteAllText(_keyPath, _pem);

        GitHubPrivateKeySource source = new(new GitHubOptions { PrivateKeyPath = _keyPath });

        Assert.Equal(_pem, source.ReadPem());

        File.Delete(_keyPath);

        Assert.Equal(_pem, source.ReadPem());
    }
}
