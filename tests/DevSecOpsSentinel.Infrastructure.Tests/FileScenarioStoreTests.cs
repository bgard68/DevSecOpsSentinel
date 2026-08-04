using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Infrastructure;

namespace DevSecOpsSentinel.Infrastructure.Tests;

public sealed class FileScenarioStoreTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        $"sentinel-scenarios-{Guid.NewGuid():N}");

    public FileScenarioStoreTests() => Directory.CreateDirectory(_directory);

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    [Theory]
    [InlineData("../escaped.yml")]
    [InlineData("nested/../../escaped.yml")]
    public void A_file_name_that_escapes_the_scenario_directory_is_refused(
        string fileName)
    {
        // Path.Combine silently discards the directory when the second argument
        // climbs out of it, so without a guard the store would read a file it
        // was never meant to reach.
        Write("scenarios.json",
            $"[{{\"id\":\"x\",\"name\":\"X\",\"description\":\"d\",\"fileName\":\"{fileName}\"}}]");

        File.WriteAllText(
            Path.Combine(Path.GetDirectoryName(_directory)!, "escaped.yml"),
            "name: escaped");

        FileScenarioStore store = new(_directory);

        InvalidOperationException error =
            Assert.Throws<InvalidOperationException>(() => store.GetById("x"));

        Assert.Contains("outside", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void An_ordinary_file_name_still_resolves()
    {
        Write("scenarios.json",
            "[{\"id\":\"safe\",\"name\":\"Safe\",\"description\":\"d\",\"fileName\":\"safe.yml\"}]");
        Write("safe.yml", "name: Safe");

        ScenarioDetail? scenario = new FileScenarioStore(_directory).GetById("safe");

        Assert.NotNull(scenario);
        Assert.Equal("name: Safe", scenario!.Content);
    }

    private void Write(string name, string content) =>
        File.WriteAllText(Path.Combine(_directory, name), content);
}
