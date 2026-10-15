namespace DevSecOpsSentinel.Infrastructure.Ai;

/// <summary>
/// How the deployment is configured to answer an AI explanation request.
/// </summary>
public enum WorkflowAiMode
{
    /// <summary>A complete, correctly labelled explanation that reached nothing.</summary>
    Mock,

    /// <summary>A real request to OpenAI, subject to the containment gate.</summary>
    Live,

    /// <summary>No explanation offered at all.</summary>
    Disabled
}

/// <summary>
/// The one interpretation of the <c>OpenAI:Mode</c> setting.
///
/// That setting used to be read as a string in four places: the composition root switched on
/// its upper-cased form to choose a provider, the readiness probe compared it to "Live" to
/// decide whether a missing key was a degradation, the AI status endpoint compared it to
/// "Disabled" to report whether the feature was on, and both endpoints echoed the raw
/// configured string back as the mode.
///
/// Four readings of one value, none of them agreeing on what an unrecognised value means.
/// The composition root treated anything it did not recognise as Mock and said nothing,
/// while the endpoints reported the string as configured — so <c>Mode: "Lve"</c> ran the mock
/// provider while the badge in the user interface read "Lve", and nothing anywhere said the
/// two had diverged. A deployment could believe it was live, be told it was live, and be
/// mocked.
///
/// Parsing happens here, once. What the endpoints report is the mode that was resolved, so
/// the reported mode is the provider that will actually answer.
/// </summary>
public static class WorkflowAiModes
{
    /// <summary>
    /// What an unrecognised setting resolves to. Mock rather than Disabled or Live, because
    /// it is the only value that neither spends credits nor withdraws the feature.
    /// </summary>
    public const WorkflowAiMode Fallback = WorkflowAiMode.Mock;

    /// <summary>
    /// Matched against the mode names only. <see cref="Enum.TryParse{T}(string, bool, out T)"/>
    /// would also accept "1" and "0", which are not values anyone would configure
    /// deliberately and would silently mean Live and Mock.
    /// </summary>
    public static bool TryParse(string? value, out WorkflowAiMode mode)
    {
        string candidate = value?.Trim() ?? string.Empty;

        foreach (WorkflowAiMode known in Enum.GetValues<WorkflowAiMode>())
        {
            if (candidate.Equals(known.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                mode = known;
                return true;
            }
        }

        mode = Fallback;
        return false;
    }

    public static WorkflowAiMode Resolve(string? value) =>
        TryParse(value, out WorkflowAiMode mode) ? mode : Fallback;
}
