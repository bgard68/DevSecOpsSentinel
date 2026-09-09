using DevSecOpsSentinel.Api.Security;

namespace DevSecOpsSentinel.Api.Integration.Tests;

/// <summary>
/// Unit tests for the startup gate on API security configuration. Every branch
/// here decides whether a deployment is allowed to boot, so a false positive
/// ships an unauthenticated production API.
/// </summary>
public sealed class ApiSecurityOptionsTests
{
    /// <summary>
    /// Built at runtime rather than written as a literal. A 32-character
    /// hex-shaped constant sitting next to the name "key" is exactly what
    /// gitleaks and CodeQL exist to flag, and a test fixture has no business
    /// training anyone to wave that shape through.
    /// </summary>
    private static readonly string ValidKey = new('k', 32);

    // ------------------------------------------------------------ Mode flags

    [Theory]
    [InlineData("Required", true, false, true)]
    [InlineData("required", true, false, true)]
    [InlineData("Public", false, true, true)]
    [InlineData("PUBLIC", false, true, true)]
    [InlineData("Disabled", false, false, false)]
    [InlineData("nonsense", false, false, false)]
    public void ModeFlags_ConfiguredMode_ClassifyTheDeploymentCaseInsensitively(
        string mode,
        bool expectedRequired,
        bool expectedPublic,
        bool expectedUsesApiKey)
    {
        // Arrange
        ApiSecurityOptions options = new() { Mode = mode, ApiKey = ValidKey };

        // Act & Assert
        Assert.Equal(expectedRequired, options.IsRequired);
        Assert.Equal(expectedPublic, options.IsPublicScanner);
        Assert.Equal(expectedUsesApiKey, options.UsesApiKey);
    }

    [Fact]
    public void Mode_NotSupplied_DefaultsToRequiredRatherThanDisabled()
    {
        // Arrange & Act. A missing Security:Mode must fail closed; defaulting to
        // Disabled would silently drop authentication on a misconfigured deploy.
        ApiSecurityOptions options = new();

        // Assert
        Assert.Equal(ApiSecurityOptions.RequiredMode, options.Mode);
        Assert.True(options.IsRequired);
        Assert.Equal("X-API-Key", options.HeaderName);
        Assert.Empty(options.AllowedOrigins);
    }

    // ------------------------------------------------- IsValidForEnvironment

    [Fact]
    public void IsValidForEnvironment_RequiredModeWithA32CharacterKey_ReturnsTrue()
    {
        // Arrange
        ApiSecurityOptions options = new() { Mode = "Required", ApiKey = ValidKey };

        // Act
        bool valid = options.IsValidForEnvironment("Production");

        // Assert
        Assert.Equal(32, ValidKey.Length);
        Assert.True(valid);
    }

    [Fact]
    public void IsValidForEnvironment_RequiredModeWithA31CharacterKey_ReturnsFalse()
    {
        // Arrange. The boundary is the whole control. One character below it has
        // to fail, or the length check is decoration.
        ApiSecurityOptions options = new()
        {
            Mode = "Required",
            ApiKey = ValidKey[..31]
        };

        // Act
        bool valid = options.IsValidForEnvironment("Production");

        // Assert
        Assert.False(valid);
    }

    [Fact]
    public void IsValidForEnvironment_RequiredModeWithAWhitespaceKey_ReturnsFalse()
    {
        // Arrange. A long run of spaces clears the length test but is not a key.
        ApiSecurityOptions options = new()
        {
            Mode = "Required",
            ApiKey = new string(' ', 40)
        };

        // Act
        bool valid = options.IsValidForEnvironment("Production");

        // Assert
        Assert.False(valid);
    }

    [Fact]
    public void IsValidForEnvironment_RequiredModeWithAnEmptyHeaderName_ReturnsFalse()
    {
        // Arrange
        ApiSecurityOptions options = new()
        {
            Mode = "Required",
            ApiKey = ValidKey,
            HeaderName = "   "
        };

        // Act
        bool valid = options.IsValidForEnvironment("Production");

        // Assert
        Assert.False(valid);
    }

    [Theory]
    [InlineData("Development", true)]
    [InlineData("development", true)]
    [InlineData("Testing", true)]
    [InlineData("Production", false)]
    [InlineData("Staging", false)]
    public void IsValidForEnvironment_DisabledMode_IsAcceptedOnlyInDevelopmentAndTesting(
        string environmentName,
        bool expected)
    {
        // Arrange. Disabled is a local convenience. Allowing it anywhere else
        // publishes an open API.
        ApiSecurityOptions options = new() { Mode = "Disabled" };

        // Act
        bool valid = options.IsValidForEnvironment(environmentName);

        // Assert
        Assert.Equal(expected, valid);
    }

    [Fact]
    public void IsValidForEnvironment_PublicModeWithoutAKey_ReturnsFalse()
    {
        // Arrange. Public opens deterministic analysis, but still guards the
        // endpoints that borrow a credential, so it needs the key too.
        ApiSecurityOptions options = new() { Mode = "Public", ApiKey = string.Empty };

        // Act
        bool valid = options.IsValidForEnvironment("Production");

        // Assert
        Assert.False(valid);
    }

    // -------------------------------------------------- GetValidationFailure

    [Fact]
    public void GetValidationFailure_DisabledModeInProduction_NamesTheModeConstraint()
    {
        // Arrange
        ApiSecurityOptions options = new() { Mode = "Disabled" };

        // Act
        string message = options.GetValidationFailure("Production");

        // Assert
        Assert.Equal(
            "Security:Mode must be Required or Public outside Development and Testing.",
            message);
    }

    [Fact]
    public void GetValidationFailure_RequiredModeWithAShortKey_NamesTheKeyAndTheMode()
    {
        // Arrange
        ApiSecurityOptions options = new() { Mode = "Required", ApiKey = "too-short" };

        // Act
        string message = options.GetValidationFailure("Production");

        // Assert
        Assert.Equal(
            "Security:ApiKey must contain at least 32 characters when Security:Mode is Required.",
            message);
    }

    [Fact]
    public void GetValidationFailure_PublicModeWithAShortKey_EchoesPublicAsTheMode()
    {
        // Arrange. The message quotes the configured mode back, so an operator
        // reading the log knows which setting to correct.
        ApiSecurityOptions options = new() { Mode = "Public", ApiKey = "too-short" };

        // Act
        string message = options.GetValidationFailure("Production");

        // Assert
        Assert.Equal(
            "Security:ApiKey must contain at least 32 characters when Security:Mode is Public.",
            message);
    }

    [Fact]
    public void GetValidationFailure_RequiredModeWithAValidKeyButNoHeaderName_NamesTheHeader()
    {
        // Arrange
        ApiSecurityOptions options = new()
        {
            Mode = "Required",
            ApiKey = ValidKey,
            HeaderName = string.Empty
        };

        // Act
        string message = options.GetValidationFailure("Production");

        // Assert
        Assert.Equal("Security:HeaderName is required.", message);
    }

    [Fact]
    public void GetValidationFailure_DisabledModeInDevelopment_FallsThroughToTheGenericMessage()
    {
        // Arrange. This configuration is actually valid, so the method has no
        // specific complaint to make and returns its catch-all.
        ApiSecurityOptions options = new() { Mode = "Disabled" };

        // Act
        string message = options.GetValidationFailure("Development");

        // Assert
        Assert.True(options.IsValidForEnvironment("Development"));
        Assert.Equal("API security configuration is invalid.", message);
    }
}
