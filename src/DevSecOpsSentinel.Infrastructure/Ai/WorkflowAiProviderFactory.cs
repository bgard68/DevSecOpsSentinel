using DevSecOpsSentinel.Application;
using Microsoft.Extensions.Logging;

namespace DevSecOpsSentinel.Infrastructure.Ai;

/// <summary>
/// Builds the provider the configured mode asks for.
///
/// This lived in the composition root as a switch over the upper-cased mode string, which
/// made it the one piece of provider-selection logic no test could reach without starting a
/// web host, and gave the decision a silent default: any value the switch did not recognise
/// produced the mock provider with nothing logged. A misspelled mode is a deployment that
/// believes it is live and is not, and the symptom — plausible explanations, no spend — is
/// one nobody investigates.
///
/// An unrecognised mode still resolves to Mock, because refusing to start over a wrong
/// setting is the worse failure: it has to be diagnosed through deployment logs, while a
/// warning is read beside the behaviour it explains. That is the same trade the startup host
/// and CORS checks make.
/// </summary>
public static class WorkflowAiProviderFactory
{
    public static IWorkflowAiProvider Create(
        OpenAiOptions options,
        ILoggerFactory loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(loggerFactory);

        if (!WorkflowAiModes.TryParse(options.Mode, out WorkflowAiMode mode))
        {
            loggerFactory
                .CreateLogger(typeof(WorkflowAiProviderFactory).FullName!)
                .LogWarning(
                    "OpenAI:Mode is {ConfiguredMode}, which is not a recognised mode. "
                    + "Falling back to {Mode}. Recognised modes are {RecognisedModes}.",
                    string.IsNullOrWhiteSpace(options.Mode) ? "empty" : options.Mode,
                    mode,
                    string.Join(", ", Enum.GetNames<WorkflowAiMode>()));
        }

        return mode switch
        {
            WorkflowAiMode.Live => new OpenAiWorkflowAiProvider(
                options,
                loggerFactory.CreateLogger<OpenAiWorkflowAiProvider>()),
            WorkflowAiMode.Disabled => new DisabledWorkflowAiProvider(),
            _ => new MockWorkflowAiProvider()
        };
    }
}
