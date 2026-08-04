using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DevSecOpsSentinel.Infrastructure.GitHub;

public sealed class GitHubAppJwtFactory(
    GitHubOptions options,
    IGitHubPrivateKeySource privateKeySource)
{
    public string CreateToken(DateTimeOffset now)
    {
        if (!options.IsConfigured)
        {
            throw new InvalidOperationException("GitHub App configuration is incomplete.");
        }

        string header = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(new
        {
            alg = "RS256",
            typ = "JWT"
        }));

        string payload = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(new
        {
            iat = now.AddSeconds(-60).ToUnixTimeSeconds(),
            exp = now.AddMinutes(9).ToUnixTimeSeconds(),
            iss = options.AppId.ToString(System.Globalization.CultureInfo.InvariantCulture)
        }));

        string unsignedToken = $"{header}.{payload}";
        using RSA rsa = RSA.Create();
        rsa.ImportFromPem(privateKeySource.ReadPem());
        byte[] signature = rsa.SignData(
            Encoding.ASCII.GetBytes(unsignedToken),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        return $"{unsignedToken}.{Base64UrlEncode(signature)}";
    }

    private static string Base64UrlEncode(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
