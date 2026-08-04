namespace DevSecOpsSentinel.Api.Operational;

/// <summary>
/// Operational tuning read through <c>IOptionsMonitor</c> rather than captured
/// during startup.
///
/// The request budget was previously read into a local while <c>Program.cs</c>
/// executed, which meant configuration applied later in host building — as
/// <c>WebApplicationFactory</c> does — never reached the limiter. The setting was
/// documented as configurable but was fixed at whatever the base configuration
/// said, and the rejection path could not be reached in a test without firing
/// the full production budget.
/// </summary>
public sealed class OperationalOptions
{
    public const string SectionName = "Operational";

    public string CorrelationIdHeader { get; init; } = "X-Correlation-ID";

    public int WorkflowRequestLimitPerMinute { get; init; } = 30;

    /// <summary>
    /// Reading from GitHub is cheaper than analysis but still spends this
    /// deployment's standing against GitHub's own limits, so it is bounded at a
    /// multiple of the analysis budget rather than left unbounded.
    /// </summary>
    public int GitHubReadLimitPerMinute => Math.Max(1, WorkflowRequestLimitPerMinute * 4);
}
