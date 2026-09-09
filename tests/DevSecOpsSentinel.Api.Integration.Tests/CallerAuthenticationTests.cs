using DevSecOpsSentinel.Api.Security;

namespace DevSecOpsSentinel.Api.Integration.Tests;

/// <summary>
/// Unit tests for the per-request authentication marker. It is what carries the
/// middleware's decision to the endpoint, and the endpoint spends money on the
/// strength of it, so the default has to be the closed one.
/// </summary>
public sealed class CallerAuthenticationTests
{
    [Fact]
    public void HasValidApiKey_FreshlyConstructed_DefaultsToFalse()
    {
        // Arrange & Act
        CallerAuthentication caller = new();

        // Assert
        Assert.False(caller.HasValidApiKey);
    }

    [Fact]
    public void AiAccess_NoKeyPresented_ResolvesToMockOnly()
    {
        // Arrange. This is the anonymous caller. A default of Full would let an
        // unidentified visitor drive live model calls on a deployment
        // configured for them.
        CallerAuthentication caller = new();

        // Act
        AiAccess access = caller.AiAccess;

        // Assert
        Assert.Equal(AiAccess.MockOnly, access);
    }

    [Fact]
    public void AiAccess_AfterMarkAuthenticated_ResolvesToFull()
    {
        // Arrange
        CallerAuthentication caller = new();

        // Act
        caller.MarkAuthenticated();

        // Assert
        Assert.True(caller.HasValidApiKey);
        Assert.Equal(AiAccess.Full, caller.AiAccess);
    }

    [Fact]
    public void MarkAuthenticated_CalledTwice_RemainsAuthenticatedAndIdempotent()
    {
        // Arrange
        CallerAuthentication caller = new();

        // Act
        caller.MarkAuthenticated();
        caller.MarkAuthenticated();

        // Assert
        Assert.Equal(AiAccess.Full, caller.AiAccess);
    }

    [Fact]
    public void AiAccess_TwoSeparateInstances_DoNotShareAuthenticationState()
    {
        // Arrange. The marker is registered scoped. If the flag were static,
        // one authenticated request would promote every concurrent anonymous
        // one to Full for the lifetime of the process.
        CallerAuthentication authenticated = new();
        CallerAuthentication anonymous = new();

        // Act
        authenticated.MarkAuthenticated();

        // Assert
        Assert.Equal(AiAccess.Full, authenticated.AiAccess);
        Assert.Equal(AiAccess.MockOnly, anonymous.AiAccess);
    }
}
