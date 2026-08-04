namespace DevSecOpsSentinel.Application;

public sealed record ScenarioSummary(
    string Id,
    string Name,
    string Description,
    string FileName);

public sealed record ScenarioDetail(
    string Id,
    string Name,
    string Description,
    string FileName,
    string Content);

public interface IScenarioStore
{
    IReadOnlyList<ScenarioSummary> GetAll();
    ScenarioDetail? GetById(string id);
}
