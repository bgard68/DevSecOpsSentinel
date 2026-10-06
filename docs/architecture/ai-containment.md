# AI containment

ADR-003 says the model is not the source of truth. This is how that is enforced,
which attacks it stops, and what it deliberately does not cover.

Read this before changing anything in `Infrastructure/Ai`, and before adding a
feature that asks a model for anything.

---

## The problem, stated plainly

We scan GitHub Actions workflows with deterministic rules and produce findings —
`GHA001` (unpinned action), `GHA002` (excessive permissions), and nine more. We
then ask a language model to explain those findings in prose, because a rule id
is not advice.

That is a useful feature and a genuine hazard. A model can be prompt-injected by
text inside the very workflow file it is reading. It can also simply hallucinate.
Either way there are two failure modes, and they are equally bad:

- **Inventing a finding** — an engineer spends a morning fixing a vulnerability
  that was never there, and the next report gets trusted a little less.
- **Suppressing a real one** — a genuine flaw ships because the summary never
  mentioned it.

Containment exists because both must be impossible, not unlikely.

---

## The shape of the solution

The model never decides anything. The rules decide; the model describes what was
already decided. The verdict is computed first and handed to the model as
**input**, and there is no return path from prose back into findings.

```
WorkflowExplanationService                    (Application)
  │
  ├─ 1. analysis  = AnalyzeAsync(document)    ← verdict decided, immutable
  ├─ 2. sanitized = Sanitize(content)         ← secrets redacted
  ├─ 3. if (!IsValid || !useAi) → fallback    ← model never called
  │
  └─ 4. provider.ExplainAsync(analysis, sanitized)
            │
            ▼
     OpenAiWorkflowAiProvider                 (Infrastructure.Ai)
       5. prompt  = findings + sanitized excerpt
       6. GATE: strict JSON schema, enforced by the API
       7. ──────────────► OpenAI
       8. deserialize
       9. GATE: IsValid(payload, analysis)
      10. any failure → deterministic fallback
            │
            ▼
     WorkflowExplanationResult(Analysis, Explanation)
                            ▲              ▲
                         verdict        prose
                    two records, never merged
```

The two records at the bottom are the structural guarantee.
`WorkflowAnalysisResult` holds `IsValid`, `ValidationErrors`, `Findings`,
`FindingCount` and the `Patch`. `WorkflowAiExplanation` holds prose. They are
composed side by side and never merged, so **there is no field on the analysis
that an AI type could write to**.

---

## The gate

```csharp
internal static bool IsValid(OpenAiExplanationPayload payload, WorkflowAnalysisResult analysis)
{
    HashSet<string> expected = analysis.Findings
        .Select(f => f.RuleId).ToHashSet(StringComparer.Ordinal);

    HashSet<string> received = payload.Findings
        .Select(f => f.RuleId).ToHashSet(StringComparer.Ordinal);

    return expected.SetEquals(received)
        && !string.IsNullOrWhiteSpace(payload.Summary)
        && !string.IsNullOrWhiteSpace(payload.RecommendedNextStep);
}
```

Three properties, each load-bearing:

**A set, not a list.** Order carries no meaning, so nothing can be smuggled
through position — and duplicates collapse, so padding a reply with a repeated
id to fix a count does not work.

**`StringComparer.Ordinal`, not `OrdinalIgnoreCase`.** Near misses are rejected
rather than normalised into acceptance. If a model cannot reproduce an id
exactly, we do not get to assume we know which one it meant.

**The prose checks.** A reply with perfect ids and an empty summary is still
rejected. An explanation that explains nothing is not a successful explanation.

### Why set equality and not a count

This is the question that comes up in review every time, so it is worth walking
through the four attacks in order. The scanner found two real things,
`GHA001` and `GHA002`.

| # | Attack | Model returns | Count check | `SetEquals` |
| --- | --- | --- | --- | --- |
| 1 | Invent a finding | `{GHA001, GHA002, GHA999}` | rejects | rejects |
| 2 | Drop a real finding | `{GHA001}` | rejects | rejects |
| 3 | **Swap one for another** | `{GHA001, GHA999}` | **accepts** | rejects |
| 4 | **Near-miss the id** | `{" GHA001"}` | **accepts** | rejects |

Attacks 1 and 2 are the obvious moves and anything catches them. Attack 3 is the
one that matters: keep the arithmetic honest and change the contents. A count
comparison sees `2 == 2` and waves it through, so the reader is told about a
vulnerability that does not exist *and* never hears about one that does — two
failures in one reply, through a gate that reported success.

Attack 4 is subtler: a reply that looks right to a human skim, differing only in
case or whitespace.

### Containment runs in both directions

Set equality catches fabrication and suppression with one operator. That is
deliberate. A reply that quietly omits a real finding would let the model decide
something is not worth mentioning, which is the same authority as inventing a
finding, pointed the other way.

---

## Prove it rather than trust it

Replace `SetEquals` with the count comparison a reasonable person might have
written:

```csharp
// deliberately weakened
return expected.Count == received.Count
    && !string.IsNullOrWhiteSpace(payload.Summary)
    && !string.IsNullOrWhiteSpace(payload.RecommendedNextStep);
```

**Five of fourteen containment tests fail**, and they are precisely the attacks
above:

| Test | Count check | `SetEquals` |
| --- | --- | --- |
| `ReplySwappingOneRealRuleForAnother_IsRejected` | FAIL | pass |
| `ReplyOfOnlyInventedRules_IsRejected` | FAIL | pass |
| `RuleIdPrefixMatch_IsRejectedAsNotExact("gha001")` | FAIL | pass |
| `RuleIdPrefixMatch_IsRejectedAsNotExact(" GHA001")` | FAIL | pass |
| `RuleIdPrefixMatch_IsRejectedAsNotExact("GHA001 ")` | FAIL | pass |

The tests were not written to cover lines; they were written to be the
adversary. That is the difference between a suite that reports coverage and one
that reports safety.

`tests/DevSecOpsSentinel.Infrastructure.Tests/AiContainmentTests.cs`

---

## The five gates, and where each is set

| # | Gate | What it stops | Where |
| --- | --- | --- | --- |
| 1 | Verdict computed first | The model influencing a finding at all | `WorkflowExplanationService.cs` |
| 2 | Redaction | Secrets reaching the provider | `SensitiveDataSanitizer.cs` |
| 3 | Strict JSON schema | Free-form text; invented *fields* | `OpenAiWorkflowAiProvider.cs` |
| 4 | `IsValid` set equality | Invented, dropped, swapped, near-miss ids | `OpenAiWorkflowAiProvider.cs` |
| 5 | Uniform fallback | Any failure becoming a trusted answer | `WorkflowExplanationService.cs` |

The split is not arbitrary. Gates 1 and 5 are in **Application** because they are
policy, and policy does not belong next to a vendor SDK. Gates 2, 3 and 4 are in
**Infrastructure.Ai** because they concern one provider and its wire format.
Replace OpenAI with anything else and gates 1 and 5 do not move.

### Gate 1 has two short-circuits

In both of these the model is never called:

```csharp
if (!analysis.IsValid)
    explanation = CreateFallback(analysis, "Deterministic", "...YAML is invalid.");
else if (!useAi)
    explanation = CreateFallback(analysis, "Disabled", "...not requested.");
else
    explanation = await providerSelector.Select(access)
        .ExplainAsync(analysis, sanitized.Content, ct);
```

### Gate 5 is the one that gets under-rated

Invalid reply, timeout, provider unreachable, no API key configured — four
different failures, **one destination**. There is no path anywhere that returns
something degraded but still trusted.

---

## How the code reaches a model at all

One HTTPS call to OpenAI's hosted API. No model runs on our infrastructure:
there is no container, no local runtime, no GPU. The only AI package in the
solution is the official `OpenAI` SDK, and `using OpenAI` appears in **exactly
one file** across the entire codebase.

That call is isolated behind a delegate so every other part of the pipeline is
testable with no network:

```csharp
internal delegate Task<string> CompleteChat(
    IReadOnlyList<ChatMessage> messages,
    ChatCompletionOptions options,
    CancellationToken cancellationToken);

// production: build a real client, but only if a key exists
if (!string.IsNullOrWhiteSpace(options.ApiKey)) {
    ChatClient client = new(options.Model, options.ApiKey);
    _completeChat = async (m, o, ct) =>
        (await client.CompleteChatAsync([.. m], o, ct)).Content[0].Text;
}
```

The seam exists for a specific reason, recorded on the delegate: with the
`ChatClient` built internally, *prompt assembly, the timeout envelope, payload
parsing, the containment gate and every fallback* were unreachable offline. The
replay corpus could prove the pipeline **up to** the gate but never **through**
it.

Note the `if`. With no API key configured — which is how this runs in Azure
today — `_completeChat` is **null** and every request takes the deterministic
fallback. The feature degrades to absent rather than broken.

---

## What makes the analysis deterministic

"Deterministic" means one specific thing: same workflow in, same findings out,
every time, with no model involved. Four properties hold it up.

**The rules are pure functions.** `Evaluate(ParsedWorkflow)` takes parsed YAML
and returns findings. No clock, no network, no randomness, no database.

**No state survives an evaluation.** `RuleDiscovery.All()` hands out a fresh
instance per call, so one caller's edit cannot reach another's.

**Order is pinned.** Discovery sorts by rule id with `StringComparer.Ordinal`,
so results never depend on the order the runtime happens to return types in —
which is not guaranteed to be stable.

**The model is downstream of the verdict.** The non-deterministic component runs
after the deterministic one and can only produce prose.

The proof is operational rather than theoretical: in Azure, no API key is
deployed, so the deterministic path is not a fallback nobody exercises — it is
the only path production takes.

---

## Rule identity

Two questions get conflated here and the answers are opposite.

### The ids are ours, and arbitrary

`GHA001` through `GHA012` correspond to nothing at GitHub. GitHub publishes no
rule ids for this, so there was nothing to match. `GHA` is a namespace we chose
so these cannot collide with anything scanned later. There is no allocator and
no build-time check — a human types the next number into a string literal.

### The subject matter is rigorously external

Every rule implements a documented GitHub Actions attack class:

| Rule | What it implements |
| --- | --- |
| GHA001 | Supply-chain compromise via a mutable tag; GitHub's guidance is to pin to a full commit SHA |
| GHA002 / GHA009 | `GITHUB_TOKEN` least privilege, from GitHub's hardening documentation |
| GHA004 / GHA007 | The "pwn request" — the best-known Actions vulnerability class |
| GHA005 | Script injection: `${{ }}` interpolated into a `run:` body |
| GHA006 | `actions/checkout` leaving the job token readable on the runner |
| GHA010 | Self-hosted runners on public repositories, which GitHub warns against |
| GHA011 | `workflow_run` artifact poisoning |

`ActionPermissionRequirements.cs` exists because what an action requires is
documented, static and public — somebody read it rather than guessing. And
`UnsafePullRequestTargetRule` guards against false positives because some
`pull_request_target` workflows are the documented, recommended pattern. That is
the difference between a scanner that pattern-matches alarming YAML and one that
knows when the alarming thing is correct.

### A rule id is a public API

Users write ids into their own repositories:

```yaml
actions: write # sentinel:accept GHA002 - no narrower grant exists
```

So an id is depended on in four places at once: the containment gate's
`SetEquals`, acceptance comments in other people's repositories, every report a
human reads, and discovery's sort order. **Renumbering is not an option.**
Changing `GHA002` would silently break every acceptance comment anyone has
written, and a broken acceptance either re-raises a finding somebody consciously
accepted or stops raising one they did not. Ids are append-only; nothing is
reused.

### Before you add GHA013

**The next free number is 013, not 012.** `GHA012` is already taken, and not by
a rule class — so reflection over `Rules/` will not reveal it:

```csharp
// Application/WorkflowAnalysisService.cs
private const string StaleSuppressionRuleId = "GHA012";
```

It is issued by the analysis service for a stale acceptance comment whose
finding no longer exists.

**Nothing enforces uniqueness.** Two classes declaring `GHA007` would both be
discovered, and the containment gate's `HashSet` would collapse them into one
entry — so a duplicated id could make a real finding invisible to the gate's own
accounting. The test does not exist yet:

```csharp
Assert.Equal(
    RuleDiscovery.All().Count,
    RuleDiscovery.All().Select(r => r.RuleId).Distinct().Count());
```

---

## What containment does not cover

The gate validates **which** findings are discussed. It does not validate **what
is said** about them. A reply naming the correct `GHA001` with misleading advice
passes every gate.

That is a deliberate boundary rather than an oversight: ADR-003 draws the line at
the decision, and the decision is which findings exist. The prose is prose.

It is worth stating out loud because it is the first thing a reviewer should ask,
and the answer is better given than discovered. If you want to close it, the
obvious move — have a second model judge the first — hands judgement back to a
model and reopens exactly the hole this design closes.

---

## If you are changing something here

- **Adding a provider?** Implement `IWorkflowAiProvider` in `Infrastructure/Ai`.
  Gates 1 and 5 already cover you; gates 3 and 4 are yours to reimplement for
  your wire format. Look at `MockWorkflowAiProvider` and
  `DisabledWorkflowAiProvider` first — both satisfy the same port with no SDK.
- **Changing the gate?** Weaken it deliberately, run
  `AiContainmentTests`, and confirm the failures are the ones you expected.
  A change that breaks none of them has probably not changed anything.
- **Adding a rule?** See [rules.md](rules.md). The containment gate needs no
  change — it compares against whatever the scanner produced.
- **Writing a new test here?** Make it fail against the unfixed code first. A
  test that passes before and after is documentation, not a test.

## See also

| | |
| --- | --- |
| [../adr/ADR-003-ai-is-not-source-of-truth.md](../adr/ADR-003-ai-is-not-source-of-truth.md) | The decision this document implements |
| [rules.md](rules.md) | The eleven detection rules, and how to add one |
| [program-flow.md](program-flow.md) | What happens on a request, end to end |
| [README.md](README.md) | Layers, trust boundaries, deliberate exclusions |
