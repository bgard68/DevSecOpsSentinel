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
        string metadataPath = Path.Combine(_scenarioDirectory, "scenarios.json");
        string json = File.ReadAllText(metadataPath);
        _scenarios = JsonSerializer.Deserialize<ScenarioSummary[]>(json,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? throw new InvalidOperationException("Scenario metadata could not be loaded.");
    }

    public IReadOnlyList<ScenarioSummary> GetAll() => _scenarios;

    public ScenarioDetail? GetById(string id)
    {
        ScenarioSummary? scenario = _scenarios.FirstOrDefault(item =>
            item.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
        if (scenario is null)
        {
            return null;
        }

        string path = Path.Combine(_scenarioDirectory, scenario.FileName);
        return new ScenarioDetail(
            scenario.Id,
            scenario.Name,
            scenario.Description,
            scenario.FileName,
            File.ReadAllText(path));
    }
}
