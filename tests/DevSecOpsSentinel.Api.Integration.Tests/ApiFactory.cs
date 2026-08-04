using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace DevSecOpsSentinel.Api.Integration.Tests;

public sealed class ApiFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.ConfigureAppConfiguration((_, configuration) =>
        {
            configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["OpenAI:Mode"] = "Mock",
                ["OpenAI:ApiKey"] = string.Empty,
                ["OpenAI:Model"] = "gpt-5-mini",
                ["GitHub:Enabled"] = "false",
                ["GitHub:AppId"] = "0",
                ["GitHub:InstallationId"] = "0",
                ["GitHub:PrivateKeyPath"] = string.Empty,
                ["GitHub:AllowedRepositories:0"] = null
            });
        });
    }
}
