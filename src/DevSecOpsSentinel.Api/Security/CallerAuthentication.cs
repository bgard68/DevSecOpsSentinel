namespace DevSecOpsSentinel.Api.Security;

/// <summary>
/// Whether the current request presented a valid API key.
///
/// Scoped, and written only by <see cref="ApiKeyAuthenticationMiddleware"/>.
/// It exists because in Public mode a request can be served without a key and
/// still be affected by whether one was supplied: an anonymous caller receives
/// Mock explanations whatever the server is configured for, so the decision has
/// to survive from the middleware to the endpoint.
/// </summary>
public sealed class CallerAuthentication
{
    public bool HasValidApiKey { get; private set; }

    public void MarkAuthenticated() => HasValidApiKey = true;

    /// <summary>
    /// What a caller in this state may ask the model to do. Anonymous callers
    /// get Mock regardless of configuration — the point is that they cannot
    /// spend anything, not that they are refused.
    /// </summary>
    public AiAccess AiAccess =>
        HasValidApiKey ? AiAccess.Full : AiAccess.MockOnly;
}

public enum AiAccess
{
    /// <summary>Canned explanations. Reaches nothing, costs nothing.</summary>
    MockOnly,

    /// <summary>Whatever the server is configured for, including Live.</summary>
    Full
}
