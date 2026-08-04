using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace DevSecOpsSentinel.Api.Integration.Tests;

public sealed class RequiredSecurityApiFactory :
    WebApplicationFactory<Program>
{
    public const string ValidApiKey =
        "test-api-key-1234567890-abcdefghijklmnopqrstuvwxyz";

    protected override void ConfigureWebHost(
        IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.ConfigureAppConfiguration(
            (_, configuration) =>
            {
                configuration.AddInMemoryCollection(
                    new Dictionary<string, string?>
                    {
                        ["OpenAI:Mode"] = "Mock",
                        ["OpenAI:ApiKey"] = string.Empty,
                        ["OpenAI:Model"] = "gpt-5-mini",
                        ["GitHub:Enabled"] = "false",
                        ["GitHub:AppId"] = "0",
                        ["GitHub:InstallationId"] = "0",
                        ["GitHub:PrivateKeyPath"] =
                            string.Empty,
                        ["GitHub:AllowedRepositories:0"] =
                            null,
                        ["Security:Mode"] = "Required",
                        ["Security:ApiKey"] = ValidApiKey,
                        ["Security:HeaderName"] =
                            "X-API-Key",
                        ["Security:AllowedOrigins:0"] =
                            "https://frontend.example.test"
                    });
            });
    }
}
