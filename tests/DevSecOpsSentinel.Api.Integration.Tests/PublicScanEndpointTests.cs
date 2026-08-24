using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using DevSecOpsSentinel.Application;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace DevSecOpsSentinel.Api.Integration.Tests;

/// <summary>
/// The endpoint's job is translation: scanner outcomes to status codes, without the
/// endpoint inventing behaviour of its own. The scanner is stubbed, so what these
/// tests pin is exactly that mapping — including that the route accepts an anonymous
/// caller, which is the property the feature exists for.
/// </summary>
public sealed class PublicScanEndpointTests : IClassFixture<PublicScanEndpointTests.Factory>
{
    private readonly HttpClient _client;

    public PublicScanEndpointTests(Factory factory) => _client = factory.CreateClient();

    [Fact]
    public async Task Completed_scan_returns_ok_with_the_findings()
    {
        HttpResponseMessage response = await _client.GetAsync("/api/public-scan/octo/app");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        // The API writes enums as strings; the reader has to agree with it.
        JsonSerializerOptions options = new(JsonSerializerDefaults.Web)
        {
            Converters = { new JsonStringEnumConverter() }
        };
        PublicScanResult? result =
            await response.Content.ReadFromJsonAsync<PublicScanResult>(options);
        Assert.NotNull(result);
        Assert.Equal(PublicScanStatus.Completed, result.Status);
        Assert.Single(result.Files);
    }

    [Fact]
    public async Task Missing_repository_maps_to_not_found()
    {
        HttpResponseMessage response = await _client.GetAsync("/api/public-scan/octo/missing");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Exhausted_quota_maps_to_service_unavailable()
    {
        HttpResponseMessage response = await _client.GetAsync("/api/public-scan/octo/quota");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    [Fact]
    public async Task Invalid_name_maps_to_bad_request()
    {
        HttpResponseMessage response = await _client.GetAsync("/api/public-scan/octo/bad");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    public sealed class Factory : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IPublicRepositoryScanner>();
                services.AddSingleton<IPublicRepositoryScanner, StubScanner>();
            });
        }
    }

    private sealed class StubScanner : IPublicRepositoryScanner
    {
        public Task<PublicScanResult> ScanAsync(
            string owner,
            string repository,
            CancellationToken cancellationToken)
        {
            DateTimeOffset now = DateTimeOffset.UnixEpoch;

            PublicScanResult result = repository switch
            {
                "missing" => PublicScanResult.Failure(
                    owner, repository, PublicScanStatus.RepositoryNotFound, "gone", now),
                "quota" => PublicScanResult.Failure(
                    owner, repository, PublicScanStatus.QuotaExhausted, "spent", now),
                "bad" => PublicScanResult.Failure(
                    owner, repository, PublicScanStatus.InvalidName, "bad name", now),
                _ => new PublicScanResult(
                    owner,
                    repository,
                    PublicScanStatus.Completed,
                    Detail: null,
                    Files:
                    [
                        new PublicScanFile(
                            "ci.yml",
                            "https://github.test/ci.yml",
                            new Domain.WorkflowAnalysisResult(
                                "ci.yml", IsValid: true, [], [], Patch: null))
                    ],
                    SkippedFiles: 0,
                    now,
                    FromCache: false)
            };

            return Task.FromResult(result);
        }
    }
}
