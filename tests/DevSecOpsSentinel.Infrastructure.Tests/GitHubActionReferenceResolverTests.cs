using System.Net;
using System.Text;
using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Infrastructure.GitHub;

namespace DevSecOpsSentinel.Infrastructure.Tests;

/// <summary>
/// Tag-to-SHA resolution against a faked GitHub git-data API. The patch generator
/// pins actions with what this returns, so a wrong answer here becomes a wrong pin
/// in a proposed remediation — the annotated-tag walk and the lightweight-tag path
/// have to agree on the commit they land on.
/// </summary>
public sealed class GitHubActionReferenceResolverTests
{
    private const string CommitSha = "1111111111111111111111111111111111111111";
    private const string AnnotatedTagSha = "2222222222222222222222222222222222222222";

    private static GitHubOptions Options() => new()
    {
        Enabled = true,
        AppId = 1,
        InstallationId = 2,
        PrivateKey = "-----BEGIN key",
        AllowedRepositories = ["octo/Sandbox"],
        ApiBaseUrl = "https://api.github.test"
    };

    private sealed class FakeTokens : IGitHubInstallationTokenProvider
    {
        public Task<string> GetTokenAsync(CancellationToken cancellationToken) =>
            Task.FromResult("token");
    }

    private sealed class FakeHttp(Func<HttpRequestMessage, HttpResponseMessage> respond)
        : HttpMessageHandler, IHttpClientFactory
    {
        public int Requests { get; private set; }
        public HttpClient CreateClient(string name) => new(this);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            return Task.FromResult(respond(request));
        }
    }

    private static HttpResponseMessage Json(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static GitHubActionReferenceResolver Resolver(FakeHttp http) =>
        new(http, Options(), new FakeTokens());

    [Theory]
    [InlineData("./local/action")]
    [InlineData("docker://alpine:3")]
    [InlineData("not-a-reference")]
    public async Task ResolveAsync_LocalDockerAndMalformedReferences_AreUnsupportedWithoutAnyRequest(string reference)
    {
        FakeHttp http = new(_ => throw new InvalidOperationException("must not be called"));

        ActionReferenceResolutionResult result =
            await Resolver(http).ResolveAsync(reference, CancellationToken.None);

        Assert.Equal(ActionReferenceResolutionStatus.Unsupported, result.Status);
        Assert.Equal(0, http.Requests);
    }

    [Fact]
    public async Task ResolveAsync_AlreadyPinnedReference_ResolvesToItselfWithoutAnyRequest()
    {
        FakeHttp http = new(_ => throw new InvalidOperationException("must not be called"));

        ActionReferenceResolutionResult result = await Resolver(http)
            .ResolveAsync($"actions/checkout@{CommitSha.ToUpperInvariant()}", CancellationToken.None);

        Assert.Equal(ActionReferenceResolutionStatus.Resolved, result.Status);
        Assert.Equal(CommitSha, result.CommitSha);
        Assert.Equal(0, http.Requests);
    }

    [Fact]
    public async Task ResolveAsync_LightweightTag_ResolvesStraightToItsCommit()
    {
        FakeHttp http = new(request => request.RequestUri!.AbsolutePath.Contains("/git/ref/tags/v4")
            ? Json($$"""{ "object": { "sha": "{{CommitSha}}", "type": "commit" } }""")
            : new HttpResponseMessage(HttpStatusCode.NotFound));

        ActionReferenceResolutionResult result =
            await Resolver(http).ResolveAsync("actions/checkout@v4", CancellationToken.None);

        Assert.Equal(ActionReferenceResolutionStatus.Resolved, result.Status);
        Assert.Equal(CommitSha, result.CommitSha);
    }

    [Fact]
    public async Task ResolveAsync_AnnotatedTag_IsDereferencedToTheCommitItWraps()
    {
        // Annotated tags point at a tag object, not the commit. Pinning to the tag
        // object's SHA would produce a reference Actions cannot check out.
        FakeHttp http = new(AnnotatedTagRoutes);

        ActionReferenceResolutionResult result =
            await Resolver(http).ResolveAsync("actions/checkout@v4", CancellationToken.None);

        Assert.Equal(ActionReferenceResolutionStatus.Resolved, result.Status);
        Assert.Equal(CommitSha, result.CommitSha);
    }

    [Fact]
    public async Task ResolveAsync_BranchReference_FallsBackToTheHeadsLookup()
    {
        FakeHttp http = new(BranchOnlyRoutes);

        ActionReferenceResolutionResult result =
            await Resolver(http).ResolveAsync("actions/checkout@main", CancellationToken.None);

        Assert.Equal(ActionReferenceResolutionStatus.Resolved, result.Status);
        Assert.Equal(CommitSha, result.CommitSha);
    }

    [Fact]
    public async Task ResolveAsync_ReferenceThatIsNeitherTagNorBranch_ReportsNotFound()
    {
        // Not Failed: the lookup worked and the answer is "no such reference". The patch
        // generator treats the two differently — NotFound is a wrong tag in the workflow,
        // Failed is GitHub being unreachable.
        FakeHttp http = new(_ => new HttpResponseMessage(HttpStatusCode.NotFound));

        ActionReferenceResolutionResult result =
            await Resolver(http).ResolveAsync("actions/checkout@nope", CancellationToken.None);

        Assert.Equal(ActionReferenceResolutionStatus.NotFound, result.Status);
        Assert.Null(result.CommitSha);
    }

    [Fact]
    public async Task ResolveAsync_TagLoop_StopsAtTheDereferenceCeiling()
    {
        // A hostile or broken repository can make tag objects point at tag objects
        // forever. The resolver must give up, not follow.
        FakeHttp http = new(EndlessTagChainRoutes);

        ActionReferenceResolutionResult result =
            await Resolver(http).ResolveAsync("actions/checkout@v4", CancellationToken.None);

        Assert.NotEqual(ActionReferenceResolutionStatus.Resolved, result.Status);
        Assert.True(http.Requests <= 7, $"made {http.Requests} requests");
    }

    // Route tables for the fake transport. They live here rather than inline so
    // that each test body states what it resolves and what it expects, and the
    // branching that belongs to the double is not read as test logic.

    private static HttpResponseMessage AnnotatedTagRoutes(HttpRequestMessage request)
    {
        string path = request.RequestUri!.AbsolutePath;
        if (path.Contains("/git/ref/tags/v4"))
            return Json($$"""{ "object": { "sha": "{{AnnotatedTagSha}}", "type": "tag" } }""");
        if (path.Contains($"/git/tags/{AnnotatedTagSha}"))
            return Json($$"""{ "object": { "sha": "{{CommitSha}}", "type": "commit" } }""");
        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    private static HttpResponseMessage BranchOnlyRoutes(HttpRequestMessage request)
    {
        string path = request.RequestUri!.AbsolutePath;
        if (path.Contains("/git/ref/tags/main"))
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        if (path.Contains("/git/ref/heads/main"))
            return Json($$"""{ "object": { "sha": "{{CommitSha}}", "type": "commit" } }""");
        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    private static HttpResponseMessage EndlessTagChainRoutes(HttpRequestMessage request)
    {
        string path = request.RequestUri!.AbsolutePath;
        if (path.Contains("/git/ref/tags/v4"))
            return Json($$"""{ "object": { "sha": "{{AnnotatedTagSha}}", "type": "tag" } }""");
        if (path.Contains("/git/tags/"))
            return Json($$"""{ "object": { "sha": "{{AnnotatedTagSha}}", "type": "tag" } }""");
        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }
}
