namespace DevSecOpsSentinel.Infrastructure.Ai;

public sealed class OpenAiOptions
{
    public const string SectionName = "OpenAI";

    /// <summary>
    /// The timeout range the provider honours.
    ///
    /// Stated here because two places need to agree about it: the provider clamps
    /// <see cref="TimeoutSeconds"/> into this range before using it, and the validator
    /// refuses a configured value outside it. Without the second, a configured 300 seconds
    /// passed validation and was then silently clamped to 120 — a setting the documentation
    /// described, the application accepted, and nothing honoured.
    /// </summary>
    public const int MinimumTimeoutSeconds = 5;

    public const int MaximumTimeoutSeconds = 120;

    /// <summary>
    /// The configured mode, as written. Read <see cref="ResolvedMode"/> to decide anything:
    /// this is the raw setting and may not name a mode that exists.
    /// </summary>
    public string Mode { get; init; } = "Mock";

    public string Model { get; init; } = "gpt-5-mini";
    public string? ApiKey { get; init; }
    public int TimeoutSeconds { get; init; } = 30;
    public int MaximumContextCharacters { get; init; } = 20_000;

    /// <summary>
    /// The mode the application will actually run in, which is what every decision and every
    /// status response should be based on. See <see cref="WorkflowAiModes"/> for why these
    /// are not the same value.
    /// </summary>
    public WorkflowAiMode ResolvedMode => WorkflowAiModes.Resolve(Mode);

    /// <summary>
    /// The resolved mode's name, for reporting. Differs from <see cref="Mode"/> only when the
    /// configured value is unrecognised or differently cased — in which case this is the
    /// truthful one.
    /// </summary>
    public string ResolvedModeName => ResolvedMode.ToString();
}
