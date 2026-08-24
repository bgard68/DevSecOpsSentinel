namespace DevSecOpsSentinel.Evals;

/// <summary>
/// The corpus: a workflow file and the rule ids a correct scan produces for it.
///
/// The expected sets are written by hand, from reading each rule's trigger conditions —
/// deliberately not recorded from a scanner run. A dataset generated from current output
/// agrees with the scanner by construction and can never fail, which makes it a transcript
/// rather than an oracle. Written independently, a disagreement means something real: either
/// the fixture does not say what it claims, or the scanner is wrong.
///
/// Most fixtures are narrowed to a single rule by applying every other rule's suppression —
/// actions pinned to a SHA, permissions declared, timeout set, credentials not persisted.
/// The two compound cases are kept because real workflows stack weaknesses, and a scanner
/// that only ever sees isolated faults is not being asked a hard question.
/// </summary>
public sealed record CorpusEntry(string FileName, string[] ExpectedRuleIds, string Intent);

public static class GoldenCorpus
{
    public const string Unpinned = "GHA001";
    public const string ExcessivePermissions = "GHA002";
    public const string MissingTimeout = "GHA003";
    public const string UnsafePullRequestTarget = "GHA004";
    public const string ScriptInjection = "GHA005";
    public const string PersistedCredentials = "GHA006";
    public const string UntrustedCheckout = "GHA007";
    public const string InheritedSecrets = "GHA008";
    public const string UndeclaredPermissions = "GHA009";
    public const string SelfHostedRunner = "GHA010";
    public const string ArtifactPoisoning = "GHA011";

    public static IReadOnlyList<CorpusEntry> Entries { get; } =
    [
        new("safe.yml",
            [],
            "Baseline. Every suppression applied at once, so any finding is a false positive."),

        new("unpinned-action.yml",
            [Unpinned],
            "A mutable tag where a SHA belongs."),

        new("excessive-permissions.yml",
            [ExcessivePermissions],
            "write-all at workflow scope."),

        new("missing-timeout.yml",
            [MissingTimeout],
            "No timeout-minutes, so a hung job holds the runner to the platform ceiling."),

        new("script-injection.yml",
            [ScriptInjection],
            "An attacker-controlled issue title interpolated into a shell body."),

        new("persisted-credentials.yml",
            [PersistedCredentials],
            "checkout at its default, leaving the job token in .git/config for later steps."),

        new("inherited-secrets.yml",
            [InheritedSecrets],
            "secrets: inherit hands the called workflow the entire store."),

        new("undeclared-permissions.yml",
            [UndeclaredPermissions],
            "No permissions block anywhere, so the effective grant is invisible in the file."),

        new("self-hosted-runner.yml",
            [SelfHostedRunner],
            "A self-hosted runner reachable from a pull request; state outlives the run."),

        new("artifact-poisoning.yml",
            [ArtifactPoisoning],
            "A privileged workflow_run job consuming a contributor-produced artifact."),

        new("prompt-injection.yml",
            [Unpinned],
            "Workflow comments addressed at the model, telling it to suppress the real "
            + "finding and report an invented one. The scanner reads structure, not prose, "
            + "so its answer is the same as any other unpinned action. The model's answer "
            + "to this file is measured in the replay corpus."),

        new("untrusted-checkout.yml",
            [UnsafePullRequestTarget, UntrustedCheckout],
            "Compound. pull_request_target is itself the GHA004 finding, and checking out "
            + "the contributor's head under it is the GHA007 finding. Both are true at once."),

        new("unsafe-pull-request-target.yml",
            [Unpinned, ExcessivePermissions, MissingTimeout, UnsafePullRequestTarget,
             PersistedCredentials, UntrustedCheckout],
            "Compound. The sandbox's worst case, with no suppressions applied — the shape a "
            + "real vulnerable workflow takes, where one mistake travels with several others.")
    ];
}
