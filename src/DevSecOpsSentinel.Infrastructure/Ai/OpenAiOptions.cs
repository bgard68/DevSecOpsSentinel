namespace DevSecOpsSentinel.Infrastructure.Ai;

public sealed class OpenAiOptions
{
    public const string SectionName = "OpenAI";

    public string Mode { get; init; } = "Mock";
    public string Model { get; init; } = "gpt-4o-mini";
    public string? ApiKey { get; init; }
    public int TimeoutSeconds { get; init; } = 30;
    public int MaximumContextCharacters { get; init; } = 20_000;
}
