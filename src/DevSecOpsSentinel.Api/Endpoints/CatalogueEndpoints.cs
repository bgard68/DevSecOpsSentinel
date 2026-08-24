using System.Text.Json;
using DevSecOpsSentinel.Api.Security;
using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;
using DevSecOpsSentinel.Infrastructure.Ai;
using DevSecOpsSentinel.Infrastructure.GitHub;
using Microsoft.AspNetCore.Mvc;

namespace DevSecOpsSentinel.Api.Endpoints;

/// <summary>
/// The rule catalogue and the bundled scenarios: what this tool looks for, and the
/// worked examples of each. Neither depends on configuration.
///
/// Extracted from Program.cs, which had grown to 944 lines holding the composition root,
/// the middleware pipeline and every handler body at once.
/// </summary>
public static class CatalogueEndpoints
{
    public static WebApplication MapCatalogueEndpoints(this WebApplication app)
    {
    app.MapGet(
        "/api/rules",
        (IEnumerable<IWorkflowSecurityRule> rules) =>
            Results.Ok(
                rules.Select(rule => new
                {
                    rule.RuleId,
                    rule.Title,
                    severity = rule.Severity.ToString()
                })
                .OrderBy(rule => rule.RuleId)))
        .CacheOutput(policy =>
            policy.Expire(TimeSpan.FromMinutes(5)));

    app.MapGet(
        "/api/scenarios",
        (IScenarioStore store) =>
            Results.Ok(store.GetAll()))
        .CacheOutput(policy =>
            policy.Expire(TimeSpan.FromMinutes(5)));

    app.MapGet(
        "/api/scenarios/{id}",
        (string id, IScenarioStore store) =>
        {
            ScenarioDetail? scenario = store.GetById(id);

            return scenario is null
                ? Results.NotFound(new ProblemDetails
                {
                    Title = "Scenario not found",
                    Detail = $"No scenario with id '{id}' exists.",
                    Status = StatusCodes.Status404NotFound
                })
                : Results.Ok(scenario);
        });

        return app;
    }
}
