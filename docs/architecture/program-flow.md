# Program flow

What actually happens when a workflow is analysed, on both sides.

---

## Backend: analysing a workflow

```
POST /api/workflows/analyze
      │
      ├─ CorrelationIdMiddleware ······ assigns or honours X-Correlation-ID
      ├─ RequestTelemetryMiddleware ··· times the request, logs sanitised path
      ├─ SecurityHeadersMiddleware ···· CSP, nosniff, frame-options
      ├─ CORS ························· origin checked against AllowedOrigins
      ├─ ApiKeyAuthenticationMiddleware  X-API-Key, when Mode is Required
      └─ Rate limiter ················· partitioned by hashed key, else by IP
      │
      ▼
WorkflowRequestValidationFilter ········ file name and content present,
      │                                  content within 100,000 characters.
      │                                  On the /api/workflows route group, so
      │                                  every endpoint under it is covered
      ▼
WorkflowAnalysisService.AnalyzeAsync
      │
      ├─ 1. WorkflowParser.Parse
      │      ├─ line model ··············· every line, with block scalar
      │      │                             bodies withheld
      │      ├─ script blocks ············ those bodies, kept separately
      │      └─ structure ················ YamlDotNet: triggers, jobs,
      │                                    permissions, steps, with line marks
      │
      ├─ 2. Each IWorkflowSecurityRule evaluates the parsed workflow
      │      └─ findings ordered by severity, then line, then rule id
      │
      └─ 3. WorkflowPatchGenerator.GenerateAsync
             ├─ asks each fixable finding's IWorkflowFix for edits
             ├─ only on lines the parser considers semantic
             ├─ applies replacements, then insertions bottom-up
             ├─ re-parses the result
             ├─ checks job count and triggers are unchanged
             ├─ re-runs every rule
             └─ rejects the patch if any rule count went up
      ▼
WorkflowAnalysisResult { findings, patch, validity }
```

### Two parsers, on purpose

`WorkflowParser` produces two views of the same document.

The **structure** comes from YamlDotNet. It answers questions about
relationships — which `with:` inputs belong to which step, which permissions
belong to which job — and carries the source line of every element. Rules that
reason about relationships read this, so flow mappings, quoted keys, anchors and
the YAML 1.1 treatment of `on` as a boolean all resolve the way GitHub resolves
them.

The **line model** answers questions about content. YAML models a `run:` block as
one opaque scalar, so per-line attribution inside it is not available from the
structure — and GHA005 needs exactly that. Line-indexed patching needs it too.

Block scalar bodies are withheld from the line model and captured separately.
Without that, a shell script containing `uses: foo@v1` produced an unpinned-action
finding, and the patch generator would have rewritten a line inside a shell
script.

### The remediation guarantee

A patch is reported valid only if all of the following hold: it re-parses; the
job count and trigger set are unchanged; and for every rule, the proposed finding
count is no greater than the original count minus the number that rule's fixes
resolved.

An action reference that cannot be resolved is left untouched, is not counted as
applied, does not reduce the risk score, and produces a warning explaining why.
Failing closed matters more than appearing to fix something.

A patch that fails validation is not offered as an improvement at all: the
proposal becomes the document as it stands, so the report claims no reduction,
resolves nothing and carries an empty diff. The previous behaviour analysed the
rejected content regardless, and since the usual reason for rejection is that the
content no longer parses — which reports no findings — that arrived as a 100%
risk reduction printed beside the same report declaring the patch invalid.

Which findings a patch resolved is recorded by the patch, per finding, rather
than inferred from which rule ids survive re-analysis. The inference could not
tell two findings of one rule apart, so fixing one of two unpinned actions left
that rule id in the surviving set and reported both as unresolved.

### The diff is bounded

The unified diff compares the document line by line, which costs memory
quadratic in the number of lines compared — measured at 15 MB for 2,000 lines
and 138 MB for 6,000. The request limit of 100,000 characters admits roughly
50,000 lines, which would have asked for about 9 GB on a host that has 1 GB.

Two things bound it. Identical leading and trailing lines are taken as context
without entering the comparison table, so a one-line change in a large workflow
compares one line against one line — which is the shape every remediation patch
actually has. Above a 16 MB budget the changed region is replaced wholesale
instead of compared, which holds the worst case at 15 MB and 16 ms.

The fallback produces a larger diff to read and a valid one that applies to the
same document. A patch git accepts is the contract; a minimal patch is not.

---

## Backend: the AI explanation

```
POST /api/workflows/explain   { useAi: true }
      │
      ▼
WorkflowExplanationService.ExplainAsync
      │
      ├─ deterministic analysis runs first and is authoritative
      ├─ SensitiveDataSanitizer redacts the excerpt
      │     private keys, known token formats, bearer tokens,
      │     --flag=value arguments, shell assignments, mapping values
      │
      ▼
OpenAiWorkflowAiProvider
      ├─ system prompt states the findings are authoritative
      ├─ response constrained by a strict JSON schema
      ├─ request bounded by a timeout
      │
      ▼
   IsValid(payload, analysis)
      └─ the rule id set the model returned must equal the
         deterministic rule id set, exactly
      │
      ├─ valid ──▶ explanation, generatedByAi: true
      └─ invalid ▶ deterministic fallback, generatedByAi: false,
                   mode still "Live", with a fallbackReason
```

The model cannot invent a finding, drop one, rename a rule or change a severity.
A response that tries is rejected and replaced. This constraint is the point of
the integration, more than the prose it returns — the rules already carry a
description and a recommendation, and the fallback produces comparable text with
no model call.

---

## Frontend: one analysis

```
App mounts
   └─ GET /api/security/status, /api/scenarios, /api/ai/status, /api/github/status
         └─ header badges reflect what is actually configured

User picks a scenario
   └─ GET /api/scenarios/{id} ─▶ fileName + content into the editor

User clicks Analyze
   └─ POST /api/workflows/analyze     (or /explain when AI is ticked)
   └─ POST /api/workflows/remediation
         │
         ▼
   Result panel
      ├─ Findings ············ sorted by severity, colour-coded
      ├─ Remediation plan ···· risk before and after, resolution warnings
      ├─ Workflow comparison · original beside proposed
      └─ AI advisor ·········· only when an explanation was requested
```

Every request passes through `apiFetch`, which attaches `X-API-Key` from
`sessionStorage` when one has been entered. The key is never bundled.

In **GitHub Sandbox** mode, three requests chain: repositories, then that
repository's workflows, then the selected workflow's content. The analyse button
stays disabled until the content arrives — a test once clicked one effect too
early and asserted against an empty panel.

### Where the client trusts the server

The client renders `severity` by comparing it to severity names, and filters
findings by the same comparison. When the API serialised that field as an
integer, nothing matched: the list rendered empty and the risk label read "Low"
on a workflow containing high-severity findings, with no error anywhere.

That contract is now pinned by a test asserting the wire format rather than a
deserialised object. See
[engineering-log.md](../engineering-log.md#1-findings-were-invisible-in-the-user-interface).

---

## Project layout

```
DevSecOpsSentinel.Domain          models, severities, no dependencies
DevSecOpsSentinel.Application     interfaces, orchestration, contracts
DevSecOpsSentinel.Infrastructure  parser, rules, GitHub, OpenAI
DevSecOpsSentinel.Api             endpoints, middleware, exports
devsecops-sentinel-web            React client
```

Dependencies point inward. Domain knows nothing of the others; Infrastructure
implements interfaces Application declares; the API composes them.

The one place this is deliberately relaxed: `ProductInfo` lives in Domain and is
read by all three, because a version derived from the assembly in one place is
better than a literal repeated in five — which is what it replaced.
