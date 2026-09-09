using System.Net;
using System.Net.Http.Json;

namespace DevSecOpsSentinel.Api.Integration.Tests;

/// <summary>
/// Integration tests over the real middleware pipeline for the headers that are
/// the browser-side half of the application's defences.
///
/// These assert values, not presence. A header whose name is checked but whose
/// value is not can be relaxed to <c>ALLOWALL</c> or <c>default-src *</c> and
/// stay green, which is the failure this file exists to prevent.
/// </summary>
public sealed class SecurityHeaderTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    private static string Single(HttpResponseMessage response, string header)
    {
        Assert.True(
            response.Headers.TryGetValues(header, out IEnumerable<string>? values),
            $"Response did not carry the {header} header.");

        return Assert.Single(values!);
    }

    // ------------------------------------------------------ Security headers

    [Fact]
    public async Task SecurityHeaders_ApiRequest_SetsTheExactHardeningValues()
    {
        // Arrange & Act
        HttpResponseMessage response = await _client.GetAsync("/api/health");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("nosniff", Single(response, "X-Content-Type-Options"));
        Assert.Equal("DENY", Single(response, "X-Frame-Options"));
        Assert.Equal("no-referrer", Single(response, "Referrer-Policy"));
        Assert.Equal(
            "camera=(), microphone=(), geolocation=()",
            Single(response, "Permissions-Policy"));
    }

    [Fact]
    public async Task SecurityHeaders_ApiRequest_SendsTheLockedDownContentSecurityPolicy()
    {
        // Arrange. An API response is never a document, so nothing is allowed to
        // load and nothing is allowed to frame it.
        HttpResponseMessage response = await _client.GetAsync("/api/health");

        // Act
        string policy = Single(response, "Content-Security-Policy");

        // Assert
        Assert.Equal(
            "default-src 'none'; frame-ancestors 'none'; " +
            "base-uri 'none'; form-action 'none'",
            policy);
    }

    [Fact]
    public async Task SecurityHeaders_ScalarDocumentationRequest_RelaxesOnlyScriptsAndStylesToTheCdn()
    {
        // Arrange. The documentation page is the one route that loads a third
        // party bundle. The relaxation has to stay scoped to that route and to
        // script-src and style-src, and must not reopen framing or form posts.
        HttpResponseMessage response = await _client.GetAsync("/scalar");

        // Act
        string policy = Single(response, "Content-Security-Policy");

        // Assert
        Assert.Equal(
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
            "img-src 'self' data:; connect-src 'self'; " +
            "font-src 'self' data:; frame-ancestors 'none'; " +
            "base-uri 'self'; form-action 'self'",
            policy);
    }

    [Fact]
    public async Task SecurityHeaders_RouteThatOnlyPrefixMatchesScalar_KeepsTheLockedDownPolicy()
    {
        // Arrange. The relaxation is selected by path. A StartsWith test without
        // segment awareness would hand the CDN allowance to any route whose name
        // merely begins with the same letters.
        HttpResponseMessage response = await _client.GetAsync("/scalarium");

        // Act
        string policy = Single(response, "Content-Security-Policy");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.DoesNotContain("cdn.jsdelivr.net", policy, StringComparison.Ordinal);
        Assert.Equal(
            "default-src 'none'; frame-ancestors 'none'; " +
            "base-uri 'none'; form-action 'none'",
            policy);
    }

    [Fact]
    public async Task SecurityHeaders_NotFoundResponse_StillCarriesTheHardeningHeaders()
    {
        // Arrange. Headers are attached from OnStarting, so they have to survive
        // a short-circuited pipeline as well as a handled route.
        HttpResponseMessage response = await _client.GetAsync("/does-not-exist");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("nosniff", Single(response, "X-Content-Type-Options"));
        Assert.Equal("DENY", Single(response, "X-Frame-Options"));
    }

    [Fact]
    public async Task SecurityHeaders_ErrorResponseFromAHandler_StillCarriesTheHardeningHeaders()
    {
        // Arrange. A validation failure returns through the problem-details
        // path rather than the endpoint result, and must not skip the headers.
        HttpResponseMessage response = await _client.PostAsJsonAsync(
            "/api/workflows/analyze",
            new { fileName = "", content = "" });

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("nosniff", Single(response, "X-Content-Type-Options"));
        Assert.Equal("DENY", Single(response, "X-Frame-Options"));
    }

    // ------------------------------------------------------- Correlation ID

    [Fact]
    public async Task CorrelationId_RequestSuppliesTheHeader_EchoesThatExactValueBack()
    {
        // Arrange
        using HttpRequestMessage request = new(HttpMethod.Get, "/api/health");
        request.Headers.Add("X-Correlation-ID", "caller-supplied-id");

        // Act
        HttpResponseMessage response = await _client.SendAsync(request);

        // Assert
        Assert.Equal("caller-supplied-id", Single(response, "X-Correlation-ID"));
    }

    [Fact]
    public async Task CorrelationId_RequestOmitsTheHeader_GeneratesAThirtyTwoCharacterHexId()
    {
        // Arrange & Act
        HttpResponseMessage response = await _client.GetAsync("/api/health");

        // Assert. The "N" format is 32 hex digits with no separators. Asserting
        // the shape is what distinguishes a generated id from an empty header
        // that a presence check would happily accept.
        string correlationId = Single(response, "X-Correlation-ID");

        Assert.Equal(32, correlationId.Length);
        Assert.True(
            Guid.TryParseExact(correlationId, "N", out _),
            $"Expected an unhyphenated GUID, got '{correlationId}'.");
    }

    [Fact]
    public async Task CorrelationId_RequestSuppliesAWhitespaceHeader_SubstitutesAGeneratedId()
    {
        // Arrange. A blank value would make every request in the log share one
        // meaningless correlation key.
        using HttpRequestMessage request = new(HttpMethod.Get, "/api/health");
        request.Headers.TryAddWithoutValidation("X-Correlation-ID", "   ");

        // Act
        HttpResponseMessage response = await _client.SendAsync(request);

        // Assert
        string correlationId = Single(response, "X-Correlation-ID");

        Assert.True(
            Guid.TryParseExact(correlationId, "N", out _),
            $"Expected a generated id to replace the blank header, got '{correlationId}'.");
    }

    [Fact]
    public async Task CorrelationId_TwoRequestsWithoutTheHeader_ReceiveDifferentGeneratedIds()
    {
        // Arrange & Act
        HttpResponseMessage first = await _client.GetAsync("/api/health");
        HttpResponseMessage second = await _client.GetAsync("/api/health");

        // Assert. A constant would correlate every request to every other one.
        Assert.NotEqual(
            Single(first, "X-Correlation-ID"),
            Single(second, "X-Correlation-ID"));
    }
}
