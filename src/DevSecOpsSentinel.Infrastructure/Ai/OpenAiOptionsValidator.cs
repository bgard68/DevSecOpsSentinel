using Microsoft.Extensions.Options;

namespace DevSecOpsSentinel.Infrastructure.Ai;

/// <summary>
/// Rejects an OpenAI configuration that cannot work, at startup.
///
/// These settings used to be read with <c>GetSection().Get&lt;T&gt;()</c> and registered as a
/// plain instance, so nothing validated them — unlike the API security options beside them,
/// which have been validated on start since they were introduced. A timeout of zero or a
/// blank model name was accepted and surfaced later as a failed request, at which point the
/// cause is a stack trace rather than a setting.
///
/// What is deliberately not validated here is <see cref="OpenAiOptions.Mode"/>. An
/// unrecognised mode is reported as a startup warning and resolves to Mock — see
/// <see cref="WorkflowAiModes"/> for why a wrong value is better surfaced than fatal — and
/// a missing API key in Live mode is reported by the readiness probe as a degradation,
/// which is the documented behaviour rather than a misconfiguration.
/// </summary>
public sealed class OpenAiOptionsValidator : IValidateOptions<OpenAiOptions>
{
    internal const int MinimumContextCharacters = 1_000;
    internal const int MaximumContextCharacters = 1_000_000;

    public ValidateOptionsResult Validate(string? name, OpenAiOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        List<string> failures = [];

        if (string.IsNullOrWhiteSpace(options.Model))
        {
            failures.Add($"{OpenAiOptions.SectionName}:Model must name a model.");
        }

        // The range the provider actually honours, read from the same constants it clamps
        // with. A value outside it is refused here rather than silently clamped there.
        if (options.TimeoutSeconds is < OpenAiOptions.MinimumTimeoutSeconds
            or > OpenAiOptions.MaximumTimeoutSeconds)
        {
            failures.Add(
                $"{OpenAiOptions.SectionName}:TimeoutSeconds must be between "
                + $"{OpenAiOptions.MinimumTimeoutSeconds} and "
                + $"{OpenAiOptions.MaximumTimeoutSeconds}, but was "
                + $"{options.TimeoutSeconds}.");
        }

        if (options.MaximumContextCharacters
            is < MinimumContextCharacters or > MaximumContextCharacters)
        {
            failures.Add(
                $"{OpenAiOptions.SectionName}:MaximumContextCharacters must be between "
                + $"{MinimumContextCharacters} and {MaximumContextCharacters}, but was "
                + $"{options.MaximumContextCharacters}.");
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}
