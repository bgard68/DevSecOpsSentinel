using System.Reflection;

namespace DevSecOpsSentinel.Domain;

/// <summary>
/// Product identity, derived from the assembly rather than repeated as literals.
///
/// The version previously appeared as a string in five places and had drifted to
/// three different values: the health endpoint and the SARIF tool descriptor
/// reported 1.0.0 against a 1.0.1 release, and two GitHub User-Agent headers
/// still said 0.4.0. Reading it from the assembly makes
/// <c>Directory.Build.props</c> the only place a version is written.
/// </summary>
public static class ProductInfo
{
    public const string Name = "DevSecOps Sentinel";

    /// <summary>
    /// The informational version without any build metadata suffix. Deterministic
    /// builds append "+&lt;commit&gt;", which is useful in diagnostics but not in a
    /// SARIF tool descriptor or a User-Agent.
    /// </summary>
    public static string Version { get; } = ResolveVersion();

    /// <summary>Value for the User-Agent header on outbound GitHub requests.</summary>
    public static string UserAgent { get; } = $"DevSecOpsSentinel/{Version}";

    private static string ResolveVersion()
    {
        Assembly assembly = typeof(ProductInfo).Assembly;

        string? informational = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion;

        if (!string.IsNullOrWhiteSpace(informational))
        {
            int metadataIndex = informational.IndexOf('+');

            return metadataIndex >= 0
                ? informational[..metadataIndex]
                : informational;
        }

        return assembly.GetName().Version?.ToString(3) ?? "0.0.0";
    }
}
