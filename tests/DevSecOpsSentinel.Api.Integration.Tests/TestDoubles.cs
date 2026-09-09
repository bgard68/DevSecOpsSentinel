using DevSecOpsSentinel.Api.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace DevSecOpsSentinel.Api.Integration.Tests;

/// <summary>
/// One record per log call, so a test can assert what was written rather than
/// that something was.
/// </summary>
public sealed record LogEntry(LogLevel Level, string Message, Exception? Exception);

/// <summary>
/// Captures log output. Logging is an external dependency of the components
/// under test here, not part of them, so it is substituted rather than mocked
/// through.
/// </summary>
public sealed class CapturingLogger<T> : ILogger<T>
{
    private readonly List<LogEntry> _entries = [];

    public IReadOnlyList<LogEntry> Entries => _entries;

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter) =>
        _entries.Add(new LogEntry(
            logLevel,
            formatter(state, exception),
            exception));
}

/// <summary>
/// A fixed <see cref="ApiSecurityOptions"/> snapshot for the CORS provider,
/// which reads its configuration through the options monitor.
/// </summary>
public sealed class StaticOptionsMonitor<T>(T value) : IOptionsMonitor<T>
{
    public T CurrentValue { get; } = value;

    public T Get(string? name) => CurrentValue;

    public IDisposable? OnChange(Action<T, string?> listener) => null;
}

/// <summary>
/// Stands in for the framework's problem-details writer so the handler's
/// fallback branch — the one that runs when the service declines to write — is
/// reachable from a test.
/// </summary>
public sealed class StubProblemDetailsService(bool writes) : IProblemDetailsService
{
    public ProblemDetailsContext? LastContext { get; private set; }

    public ValueTask<bool> TryWriteAsync(ProblemDetailsContext context)
    {
        LastContext = context;
        return ValueTask.FromResult(writes);
    }

    public ValueTask WriteAsync(ProblemDetailsContext context)
    {
        LastContext = context;
        return ValueTask.CompletedTask;
    }
}
