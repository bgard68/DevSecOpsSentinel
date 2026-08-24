# Field scan: 564 workflows from 14 real repositories

The unit tests feed the rules fixtures written to provoke them. The
[golden corpus](../tests/DevSecOpsSentinel.Evals) feeds them fixtures whose
correct answers were written down independently. This is the third kind of
input: workflows nobody wrote for a scanner at all — every workflow file in
14 widely used open-source repositories, as they were on 2026-08-24.

Two questions, neither answerable by fixtures:

1. **Does the parser survive the wild?** Real workflows use anchors, flow
   style, matrix expressions and thousand-line job graphs that no hand-written
   fixture reproduces.
2. **What do the rules actually surface at field scale?** A rule that fires on
   everything is noise; a rule that never fires is either measuring something
   rare or measuring nothing.

## Results

**564 of 564 workflows parsed.** No parse failures, no exceptions. 533 (94%)
carry at least one finding; 31 are clean.

### Findings by rule — 2,601 total

| Rule | Severity | Count | What it means at this scale |
|---|---|---:|---|
| GHA001 unpinned action | High | 796 | Mutable tags are the overwhelming norm, even in flagship repositories |
| GHA003 no job timeout | Low | 789 | The default nobody changes; a hung job holds a runner for six hours |
| GHA008 `secrets: inherit` | High | 354 | Whole secret stores forwarded to reusable workflows |
| GHA002 write permissions | High | 346 | Write grants at workflow or job scope |
| GHA006 persisted credentials | Medium | 218 | `actions/checkout` leaving the job token on disk |
| GHA009 undeclared permissions | Medium | 46 | Rarest of the hygiene findings — most large projects do declare |
| GHA004 `pull_request_target` | Critical | 27 | Privileged trigger requiring a trust boundary |
| GHA011 artifact poisoning surface | High | 20 | `workflow_run` jobs consuming contributor-produced artifacts |
| GHA010 self-hosted + PR trigger | High | 5 | Rare, and worth every one: runner state outlives the run |
| GHA005 script injection | Critical | 0 | See below |
| GHA007 untrusted checkout | Critical | 0 | See below |

The two zeroes are findings too. GHA005 matches a deliberately precise list of
attacker-controlled expressions interpolated into script bodies — its absence
across 564 mature workflows says these projects have internalised that lesson
(and that the rule is precise, not trigger-happy: 796 GHA001 hits alongside 0
GHA005 hits is a rule set discriminating, not spraying). GHA007 requires
checking out a pull request's own head *under* `pull_request_target`; all 27
GHA004 sites avoided compounding the trigger that way.

### Per repository

| Repository | Workflows | With findings | Findings |
|---|---:|---:|---:|
| pytorch/pytorch | 151 | 151 | 764 |
| grafana/grafana | 94 | 94 | 518 |
| facebook/react | 23 | 23 | 311 |
| huggingface/transformers | 57 | 54 | 178 |
| dotnet/runtime | 25 | 25 | 142 |
| vercel/next.js | 38 | 38 | 134 |
| dotnet/aspnetcore | 21 | 21 | 113 |
| nodejs/node | 42 | 42 | 91 |
| apache/airflow | 52 | 27 | 82 |
| home-assistant/core | 13 | 11 | 70 |
| microsoft/vscode | 15 | 14 | 59 |
| hashicorp/terraform | 11 | 11 | 58 |
| prometheus/prometheus | 15 | 15 | 54 |
| elastic/elasticsearch | 7 | 7 | 27 |

## What this is not

**A finding is not a vulnerability, and none of this is disclosure.** These are
healthy, actively maintained projects; most findings are hygiene (a mutable tag,
a missing timeout), and every one of them is visible to anyone who opens the
workflow file — this scan reads public files and reports what a reviewer would
see. The Critical-severity findings identify *surfaces that deserve a trust
review*, not confirmed exploits. Nothing here was probed, executed, or tested
against any live system.

It is also not a benchmark of project quality. Workflow count alone explains
most of the per-repository variance.

## Reproducing it

The scanner is this repository's own `RuleDiscovery.All()` against
`WorkflowParser` — the same code the API serves, no special build.

1. Download the `.yml`/`.yaml` files under `.github/workflows/` for each
   repository listed above (the GitHub contents API, no authentication needed).
2. Parse each with `WorkflowParser`, evaluate every rule from
   `RuleDiscovery.All()`, count findings by rule id.
3. Numbers above reflect the repositories' default branches on 2026-08-24.
   Workflows change; a rerun will drift.

kubernetes/kubernetes was in the candidate list and excluded because it keeps
no workflows under `.github/workflows/` (CI lives in Prow).
