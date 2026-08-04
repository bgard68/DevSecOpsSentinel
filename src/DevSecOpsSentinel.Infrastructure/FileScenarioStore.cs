using System.Text.Json;
using DevSecOpsSentinel.Application;

namespace DevSecOpsSentinel.Infrastructure;

public sealed class FileScenarioStore
    : IScenarioStore
{
    private readonly string _scenarioDirectory;
    private readonly IReadOnlyList<ScenarioSummary> _scenarios;

    public FileScenarioStore(string scenarioDirectory)
    {
        _scenarioDirectory = scenarioDirectory;
        string json = File.ReadAllText(
            ResolveWithin(_scenarioDirectory, "scenarios.json"));
        _scenarios = JsonSerializer.Deserialize<ScenarioSummary[]>(json,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? throw new InvalidOperationException("Scenario metadata could not be loaded.");
    }

    public IReadOnlyList<ScenarioSummary> GetAll() => _scenarios;

    /// <summary>
    /// Resolves a file name inside the scenario directory, refusing anything
    /// that would land outside it.
    ///
    /// <see cref="Path.Combine(string, string)"/> silently discards the earlier
    /// argument when a later one is rooted, so a metadata entry of
    /// <c>/etc/passwd</c> or <c>..\..\secrets.txt</c> would read a file the
    /// scenario directory does not contain. The metadata ships with the
    /// application rather than arriving from a request, so this is defence in
    /// depth rather than a fix for a live path — but a bundled file is exactly
    /// the kind of input that stops being trusted the moment someone makes it
    /// configurable.
    /// </summary>
    private static string ResolveWithin(string directory, string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName))
        {
            throw new InvalidOperationException(
                "A scenario file name is required.");
        }

        string root = Path.GetFullPath(directory);
        string resolved = Path.GetFullPath(Path.Combine(root, fileName));

        string rootWithSeparator =
            root.EndsWith(Path.DirectorySeparatorChar)
                ? root
                : root + Path.DirectorySeparatorChar;

        if (!resolved.StartsWith(rootWithSeparator, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Scenario file '{fileName}' resolves outside the scenario directory.");
        }

        return resolved;
    }

    public ScenarioDetail? GetById(string id)
    {
        ScenarioSummary? scenario = _scenarios.FirstOrDefault(item =>
            item.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
        if (scenario is null)
        {
            return null;
        }

        return new ScenarioDetail(
            scenario.Id,
            scenario.Name,
            scenario.Description,
            scenario.FileName,
            File.ReadAllText(ResolveWithin(_scenarioDirectory, scenario.FileName)));
    }
}
