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
    public void Pem_supplied_as_configuration_is_used_directly()
    {
        GitHubPrivateKeySource source = new(new GitHubOptions { PrivateKey = _pem });

        Assert.True(source.IsAvailable);
        Assert.Equal("configuration", source.Description);
        Assert.Equal(_pem.Trim(), source.ReadPem());
    }

    [Fact]
    public void Base64_encoded_pem_is_decoded()
    {
        // Deployment settings and environment variables handle line breaks
        // inconsistently, so a key pasted into one frequently arrives mangled.
        // Encoding removes the question, and a Key Vault secret stores it so.
        string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(_pem));

        GitHubPrivateKeySource source = new(new GitHubOptions { PrivateKey = encoded });

        Assert.Equal(_pem, source.ReadPem());
    }

    [Fact]
    public void The_resolved_key_actually_imports()
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
    public void A_file_path_is_used_when_no_key_is_configured()
    {
        File.WriteAllText(_keyPath, _pem);

        GitHubPrivateKeySource source = new(new GitHubOptions { PrivateKeyPath = _keyPath });

        Assert.True(source.IsAvailable);
        Assert.Equal("file", source.Description);
        Assert.Equal(_pem, source.ReadPem());
    }

    [Fact]
    public void Configuration_wins_when_both_are_supplied()
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
    public void No_key_at_all_is_reported_rather_than_guessed_at()
    {
        GitHubPrivateKeySource source = new(new GitHubOptions());

        Assert.False(source.IsAvailable);
        Assert.Equal("none", source.Description);

        InvalidOperationException error =
            Assert.Throws<InvalidOperationException>(() => source.ReadPem());

        Assert.Contains("GitHub:PrivateKey", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_missing_file_is_reported_as_unavailable()
    {
        GitHubPrivateKeySource source = new(new GitHubOptions
        {
            PrivateKeyPath = Path.Join(Path.GetTempPath(), "does-not-exist.pem")
        });

        Assert.False(source.IsAvailable);
        Assert.Throws<InvalidOperationException>(() => source.ReadPem());
    }

    [Fact]
    public void A_value_that_is_neither_pem_nor_base64_pem_says_so()
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
    public void The_key_is_read_once_and_reused()
    {
        // The JWT factory previously re-read the file on every token refresh.
        File.WriteAllText(_keyPath, _pem);

        GitHubPrivateKeySource source = new(new GitHubOptions { PrivateKeyPath = _keyPath });

        Assert.Equal(_pem, source.ReadPem());

        File.Delete(_keyPath);

        Assert.Equal(_pem, source.ReadPem());
    }
}
