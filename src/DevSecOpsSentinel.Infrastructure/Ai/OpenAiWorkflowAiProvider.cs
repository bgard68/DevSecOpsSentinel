using System.Text.Json;
using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;
using OpenAI.Chat;

namespace DevSecOpsSentinel.Infrastructure.Ai;

public sealed class OpenAiWorkflowAiProvider : IWorkflowAiProvider
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly OpenAiOptions _options;
    private readonly ChatClient? _client;

    public OpenAiWorkflowAiProvider(OpenAiOptions options)
    {
        _options = options;
        if (!string.IsNullOrWhiteSpace(options.ApiKey))
        {
            _client = new ChatClient(options.Model, options.ApiKey);
        }
    }

    public async Task<WorkflowAiExplanation> ExplainAsync(
        WorkflowAnalysisResult analysis,
        string sanitizedContent,
        CancellationToken cancellationToken)
    {
        if (_client is null)
        {
            return AiExplanationFactory.CreateFallback(
                analysis,
                "Live",
                "OpenAI is configured for live mode, but no API key is available.");
        }

        try
        {
            using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(_options.TimeoutSeconds, 5, 120)));

            string context = sanitizedContent.Length <= _options.MaximumContextCharacters
                ? sanitizedContent
                : sanitizedContent[.._options.MaximumContextCharacters];

            string findingsJson = JsonSerializer.Serialize(analysis.Findings.Select(finding => new
            {
                finding.RuleId,
                Severity = finding.Severity.ToString(),
                finding.Title,
                finding.Description,
                finding.Recommendation
            }), JsonOptions);

            List<ChatMessage> messages =
            [
                new SystemChatMessage(
                    "You are a GitHub Actions security explainer. The deterministic findings supplied by the application are authoritative. " +
                    "Do not invent findings, change rule IDs, change severities, or claim that a patch was applied. Return only JSON matching the schema."),
                new UserChatMessage($"""
                    Explain the following deterministic findings for workflow '{analysis.FileName}'.

                    FINDINGS:
                    {findingsJson}

                    SANITIZED WORKFLOW EXCERPT:
                    {context}
                    """)
            ];

            ChatCompletionOptions completionOptions = new()
            {
                ResponseFormat = ChatResponseFormat.CreateJsonSchemaFormat(
                    "workflow_security_explanation",
                    BinaryData.FromString(JsonSchema),
                    jsonSchemaIsStrict: true)
            };

            ChatCompletion completion = await _client.CompleteChatAsync(
                messages,
                completionOptions,
                timeout.Token);

            string json = completion.Content[0].Text;
            OpenAiExplanationPayload? payload = JsonSerializer.Deserialize<OpenAiExplanationPayload>(json, JsonOptions);
            if (payload is null || !IsValid(payload, analysis))
            {
                return AiExplanationFactory.CreateFallback(
                    analysis,
                    "Live",
                    "OpenAI returned an invalid structured explanation.");
            }

            return new WorkflowAiExplanation(
                payload.Summary,
                payload.Findings.Select(item => new AiFindingExplanation(
                    item.RuleId,
                    item.WhyItMatters,
                    item.RecommendedAction,
                    item.Confidence)).ToArray(),
                payload.RecommendedNextStep,
                payload.Limitations,
                true,
                "Live");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return AiExplanationFactory.CreateFallback(analysis, "Live", "The OpenAI request timed out.");
        }
        catch (Exception)
        {
            return AiExplanationFactory.CreateFallback(analysis, "Live", "The OpenAI provider was unavailable.");
        }
    }

    private static bool IsValid(OpenAiExplanationPayload payload, WorkflowAnalysisResult analysis)
    {
        HashSet<string> expected = analysis.Findings.Select(finding => finding.RuleId).ToHashSet(StringComparer.Ordinal);
        HashSet<string> received = payload.Findings.Select(finding => finding.RuleId).ToHashSet(StringComparer.Ordinal);
        return expected.SetEquals(received)
            && !string.IsNullOrWhiteSpace(payload.Summary)
            && !string.IsNullOrWhiteSpace(payload.RecommendedNextStep);
    }

    private const string JsonSchema = """
    {
      "type": "object",
      "properties": {
        "summary": { "type": "string" },
        "findings": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "ruleId": { "type": "string" },
              "whyItMatters": { "type": "string" },
              "recommendedAction": { "type": "string" },
              "confidence": { "type": "string", "enum": ["high", "medium", "low"] }
            },
            "required": ["ruleId", "whyItMatters", "recommendedAction", "confidence"],
            "additionalProperties": false
          }
        },
        "recommendedNextStep": { "type": "string" },
        "limitations": { "type": "array", "items": { "type": "string" } }
      },
      "required": ["summary", "findings", "recommendedNextStep", "limitations"],
      "additionalProperties": false
    }
    """;

    private sealed record OpenAiExplanationPayload(
        string Summary,
        IReadOnlyList<OpenAiFindingPayload> Findings,
        string RecommendedNextStep,
        IReadOnlyList<string> Limitations);

    private sealed record OpenAiFindingPayload(
        string RuleId,
        string WhyItMatters,
        string RecommendedAction,
        string Confidence);
}
