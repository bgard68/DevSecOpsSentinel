using System.Reflection;
using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;
using DevSecOpsSentinel.Infrastructure;
using NetArchTest.Rules;

namespace DevSecOpsSentinel.Api.Integration.Tests;

/// <summary>
/// The dependency directions the solution is built around, asserted against the
/// compiled assemblies: Api -> Infrastructure -> Application -> Domain.
///
/// Project references make those arrows likely, not guaranteed. A reference
/// added to unblock one feature compiles cleanly, ships, and quietly turns the
/// layering into a diagram that no longer matches the code - the same silent
/// regression mode the repository-workflow tests exist to close for CI. These
/// tests are the executable form of the arrows, and they live in this project
/// because it is the only one positioned to see all four assemblies at once.
/// </summary>
public sealed class ArchitectureTests
{
    // Each assembly is anchored through a type that actually lives in it, so
    // the compiler resolves what is under test. Loading by path or by name
    // would keep passing against a stale copy after a project is renamed.
    private static readonly Assembly DomainAssembly = typeof(WorkflowDocument).Assembly;
    private static readonly Assembly ApplicationAssembly = typeof(WorkflowAnalysisService).Assembly;
    private static readonly Assembly InfrastructureAssembly = typeof(WorkflowParser).Assembly;
    private static readonly Assembly ApiAssembly = typeof(Program).Assembly;

    private const string DomainNamespace = "DevSecOpsSentinel.Domain";
    private const string ApplicationNamespace = "DevSecOpsSentinel.Application";
    private const string InfrastructureNamespace = "DevSecOpsSentinel.Infrastructure";
    private const string ApiNamespace = "DevSecOpsSentinel.Api";

    /// <summary>
    /// Libraries that mark a boundary violation wherever they appear inward of
    /// Infrastructure. YamlDotNet and OpenAI are the two the solution actually
    /// uses, so they are the realistic leak; the web and persistence entries
    /// are pre-emptive, because the cheapest time to refuse that shortcut is
    /// before the first one compiles.
    /// </summary>
    private static readonly string[] OuterWorldLibraries =
    [
        "Microsoft.AspNetCore",
        "Microsoft.EntityFrameworkCore",
        "Microsoft.Data",
        "System.Data",
        "Dapper",
        "Npgsql",
        "YamlDotNet",
        "OpenAI",
    ];

    [Fact]
    public void Domain_Types_DependOnNoOtherLayer()
    {
        // Act
        TestResult result = Types.InAssembly(DomainAssembly)
            .ShouldNot()
            .HaveDependencyOnAny(ApplicationNamespace, InfrastructureNamespace, ApiNamespace)
            .GetResult();

        // Assert
        AssertRuleHolds(result, "Domain must not depend on any outer layer");
    }

    [Fact]
    public void Domain_Types_DependOnNoPersistenceOrWebLibrary()
    {
        // Act
        TestResult result = Types.InAssembly(DomainAssembly)
            .ShouldNot()
            .HaveDependencyOnAny(OuterWorldLibraries)
            .GetResult();

        // Assert
        AssertRuleHolds(result, "Domain must stay free of persistence and web libraries");
    }

    [Fact]
    public void Application_Types_ReachOnlyInward()
    {
        // Arrange. The vendor SDK and the YAML parser count as outward reaches
        // too: an Application type calling OpenAI or parsing YAML itself has
        // moved the boundary just as surely as one naming an Infrastructure
        // type, and nothing else would say so.
        string[] forbidden = [InfrastructureNamespace, ApiNamespace, .. OuterWorldLibraries];

        // Act
        TestResult result = Types.InAssembly(ApplicationAssembly)
            .ShouldNot()
            .HaveDependencyOnAny(forbidden)
            .GetResult();

        // Assert
        AssertRuleHolds(result, "Application may reach only inward, to Domain");
    }

    [Fact]
    public void Infrastructure_Types_NeverDependOnTheApiLayer()
    {
        // Act
        TestResult result = Types.InAssembly(InfrastructureAssembly)
            .ShouldNot()
            .HaveDependencyOnAny(ApiNamespace)
            .GetResult();

        // Assert
        AssertRuleHolds(result, "Infrastructure must never reference the Api layer");
    }

    [Fact]
    public void ProjectGraph_CompiledReferences_PointStrictlyInward()
    {
        // Arrange. GetReferencedAssemblies reads compiled metadata, so this
        // sees the references that survived compilation rather than the ones
        // the project files declare - including any the namespace rules above
        // cannot name, such as a type that lives outside its assembly's root
        // namespace the way Program does.
        string[] domainReferences = SolutionReferencesOf(DomainAssembly);
        string[] applicationReferences = SolutionReferencesOf(ApplicationAssembly);
        string[] infrastructureReferences = SolutionReferencesOf(InfrastructureAssembly);
        string[] apiReferences = SolutionReferencesOf(ApiAssembly);

        // Assert. The innermost layer references nothing of ours.
        Assert.Empty(domainReferences);

        // Each outer layer keeps its inward edge: losing one would mean the
        // layer no longer uses the one beneath it, which is a redesign this
        // test should force into the open rather than let drift decide.
        Assert.Contains(DomainNamespace, applicationReferences);
        Assert.Contains(ApplicationNamespace, infrastructureReferences);
        Assert.Contains(ApplicationNamespace, apiReferences);
        Assert.Contains(InfrastructureNamespace, apiReferences);

        // And no layer grows an outward edge. Assert.DoesNotContain prints the
        // full reference list on failure, so the offending edge names itself.
        Assert.DoesNotContain(InfrastructureNamespace, applicationReferences);
        Assert.DoesNotContain(ApiNamespace, applicationReferences);
        Assert.DoesNotContain(ApiNamespace, infrastructureReferences);
    }

    /// <summary>
    /// The solution's own assemblies referenced by <paramref name="assembly"/>.
    /// Assembly names equal project names here, which equal root namespaces,
    /// so the layer constants above are the right vocabulary for both checks.
    /// </summary>
    private static string[] SolutionReferencesOf(Assembly assembly) =>
        [.. assembly.GetReferencedAssemblies()
            .Select(reference => reference.Name ?? string.Empty)
            .Where(name => name.StartsWith("DevSecOpsSentinel.", StringComparison.Ordinal))
            .OrderBy(name => name, StringComparer.Ordinal)];

    private static void AssertRuleHolds(TestResult result, string rule)
    {
        // A failure that does not name the offending types sends the reader to
        // a diff; the type names send them to the violation.
        string offenders = string.Join(
            ", ",
            (result.FailingTypes ?? []).Select(type => type.FullName));

        Assert.True(result.IsSuccessful, $"{rule}. Offending types: {offenders}");
    }
}
