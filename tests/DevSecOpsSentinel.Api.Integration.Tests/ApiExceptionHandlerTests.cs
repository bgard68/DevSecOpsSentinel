using System.Text;
using System.Text.Json;
using DevSecOpsSentinel.Api.Operational;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace DevSecOpsSentinel.Api.Integration.Tests;

/// <summary>
/// Unit tests for the last line of the error pipeline. It decides whether a
/// failure is the caller's fault or the server's, and that choice is both the
/// status code the client sees and the log level an operator pages on.
///
/// The handler is exercised directly against a real <see cref="HttpContext"/>;
/// only the problem-details writer and the logger are substituted, because both
/// are framework services rather than parts of the unit.
/// </summary>
public sealed class ApiExceptionHandlerTests
{
    private static DefaultHttpContext Context(string method = "POST", string path = "/api/workflows/analyze")
    {
        DefaultHttpContext context = new();
        context.Request.Method = method;
        context.Request.Path = path;
        context.Response.Body = new MemoryStream();
        return context;
    }

    private static async Task<(int Status, string ContentType, ProblemDetails Problem, IReadOnlyList<LogEntry> Logs)>
        Handle(Exception exception, bool serviceWrites = true)
    {
        CapturingLogger<ApiExceptionHandler> logger = new();
        StubProblemDetailsService service = new(serviceWrites);
        DefaultHttpContext context = Context();

        bool handled = await new ApiExceptionHandler(logger, service)
            .TryHandleAsync(context, exception, CancellationToken.None);

        Assert.True(handled, "The handler must claim every exception it is given.");

        return (
            context.Response.StatusCode,
            context.Response.ContentType!,
            service.LastContext!.ProblemDetails,
            logger.Entries);
    }

    // -------------------------------------------------- Caller-side failures

    [Fact]
    public async Task TryHandleAsync_MalformedJsonBody_RespondsBadRequestWithTheInvalidBodyProblem()
    {
        // Arrange
        JsonException exception = new("Unexpected end of JSON input.");

        // Act
        var result = await Handle(exception);

        // Assert
        Assert.Equal(StatusCodes.Status400BadRequest, result.Status);
        Assert.Equal("application/problem+json", result.ContentType);
        Assert.Equal("Invalid request body", result.Problem.Title);
        Assert.Equal("The request body contains malformed JSON.", result.Problem.Detail);
        Assert.Equal(StatusCodes.Status400BadRequest, result.Problem.Status);
        Assert.Equal("/api/workflows/analyze", result.Problem.Instance);
    }

    [Fact]
    public async Task TryHandleAsync_BadHttpRequestException_IsClassifiedAsTheCallersFaultNotTheServers()
    {
        // Arrange
        BadHttpRequestException exception = new("Request body too large.");

        // Act
        var result = await Handle(exception);

        // Assert
        Assert.Equal(StatusCodes.Status400BadRequest, result.Status);
        Assert.Equal("Invalid request body", result.Problem.Title);
    }

    [Fact]
    public async Task TryHandleAsync_CallerSideFailure_LogsAWarningAndNotAnError()
    {
        // Arrange. A malformed body is routine traffic. Logging it at Error
        // level makes the error rate meaningless and pages someone for it.
        JsonException exception = new("Unexpected token.");

        // Act
        var result = await Handle(exception);

        // Assert
        LogEntry entry = Assert.Single(result.Logs);

        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Equal(
            "Rejected malformed request for POST /api/workflows/analyze",
            entry.Message);
        Assert.Null(entry.Exception);
    }

    // -------------------------------------------------- Server-side failures

    [Fact]
    public async Task TryHandleAsync_UnexpectedException_RespondsInternalServerErrorWithNoLeakedDetail()
    {
        // Arrange. The message names an internal host. It must not reach the
        // client, so Detail stays null on the server-side branch.
        InvalidOperationException exception = new(
            "Connection to sql-prod-07.internal refused.");

        // Act
        var result = await Handle(exception);

        // Assert
        Assert.Equal(StatusCodes.Status500InternalServerError, result.Status);
        Assert.Equal("Unexpected server error", result.Problem.Title);
        Assert.Null(result.Problem.Detail);
        Assert.Equal(StatusCodes.Status500InternalServerError, result.Problem.Status);
    }

    [Fact]
    public async Task TryHandleAsync_UnexpectedException_LogsAtErrorLevelCarryingTheException()
    {
        // Arrange. The stack trace is the only place the cause survives, since
        // it is deliberately withheld from the response.
        InvalidOperationException exception = new("Boom.");

        // Act
        var result = await Handle(exception);

        // Assert
        LogEntry entry = Assert.Single(result.Logs);

        Assert.Equal(LogLevel.Error, entry.Level);
        Assert.Equal(
            "Unhandled request failure for POST /api/workflows/analyze",
            entry.Message);
        Assert.Same(exception, entry.Exception);
    }

    [Fact]
    public async Task TryHandleAsync_OperationCancelled_IsTreatedAsAServerFailureNotABadRequest()
    {
        // Arrange. Cancellation is not malformed input, so it must not be
        // reported to the caller as though they sent bad JSON.
        OperationCanceledException exception = new();

        // Act
        var result = await Handle(exception);

        // Assert
        Assert.Equal(StatusCodes.Status500InternalServerError, result.Status);
        Assert.Equal("Unexpected server error", result.Problem.Title);
    }

    // ------------------------------------------------------ Fallback writing

    [Fact]
    public async Task TryHandleAsync_ProblemDetailsServiceDeclinesToWrite_WritesTheProblemBodyItself()
    {
        // Arrange. If the service declines and the handler does not step in, the
        // client receives a status code with an empty body.
        CapturingLogger<ApiExceptionHandler> logger = new();
        StubProblemDetailsService service = new(writes: false);
        DefaultHttpContext context = Context();

        // Act
        await new ApiExceptionHandler(logger, service)
            .TryHandleAsync(context, new JsonException("bad"), CancellationToken.None);

        // Assert
        context.Response.Body.Seek(0, SeekOrigin.Begin);
        using StreamReader reader = new(context.Response.Body, Encoding.UTF8);
        string body = await reader.ReadToEndAsync();

        using JsonDocument document = JsonDocument.Parse(body);

        Assert.Equal(
            "Invalid request body",
            document.RootElement.GetProperty("title").GetString());
        Assert.Equal(
            StatusCodes.Status400BadRequest,
            document.RootElement.GetProperty("status").GetInt32());
        Assert.Equal("application/problem+json", context.Response.ContentType);
    }

    [Fact]
    public async Task TryHandleAsync_ProblemDetailsServiceWrites_DoesNotAlsoWriteASecondBody()
    {
        // Arrange. Writing twice appends a second JSON document to the same
        // response and produces a payload no client can parse.
        CapturingLogger<ApiExceptionHandler> logger = new();
        StubProblemDetailsService service = new(writes: true);
        DefaultHttpContext context = Context();

        // Act
        await new ApiExceptionHandler(logger, service)
            .TryHandleAsync(context, new JsonException("bad"), CancellationToken.None);

        // Assert
        Assert.Equal(0, context.Response.Body.Length);
    }

    [Fact]
    public async Task TryHandleAsync_RequestPathDiffers_ReportsThatPathAsTheProblemInstance()
    {
        // Arrange
        CapturingLogger<ApiExceptionHandler> logger = new();
        StubProblemDetailsService service = new(writes: true);
        DefaultHttpContext context = Context("GET", "/api/scenarios/hardened");

        // Act
        await new ApiExceptionHandler(logger, service)
            .TryHandleAsync(context, new JsonException("bad"), CancellationToken.None);

        // Assert
        Assert.Equal("/api/scenarios/hardened", service.LastContext!.ProblemDetails.Instance);
        Assert.Same(context, service.LastContext.HttpContext);
    }
}
