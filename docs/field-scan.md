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

**564 of 564 workflows parsed.** No parse failures, no exceptions. 532 (94%)
carry at least one finding; 32 are clean.

### Findings by rule — 2,563 total

| Rule | Severity | Count | What it means at this scale |
|---|---|---:|---|
| GHA001 unpinned action | High | 796 | Mutable tags are the overwhelming norm, even in flagship repositories |
| GHA003 no job timeout | Low | 789 | The default nobody changes; a hung job holds a runner for six hours |
| GHA008 `secrets: inherit` | High | 354 | Whole secret stores forwarded to reusable workflows |
| GHA002 write permissions | By scope | 319 | Write grants nothing in the job requires. 27 more were examined and found required |
| GHA006 persisted credentials | Medium | 207 | `actions/checkout` leaving the job token on disk. 11 more push with it |
| GHA009 undeclared permissions | Medium | 46 | Rarest of the hygiene findings — most large projects do declare |
| GHA004 `pull_request_target` | Low | 27 | Privileged trigger requiring a trust boundary; none compounds it |
| GHA011 artifact poisoning surface | High | 20 | `workflow_run` jobs consuming contributor-produced artifacts |
| GHA010 self-hosted + PR trigger | High | 5 | Rare, and worth every one: runner state outlives the run |
| GHA005 script injection | Critical | 0 | See below |
| GHA007 untrusted checkout | Critical | 0 | See below |

### What establishing need changed

The same 564 files, before and after the three rules learned to check whether a
grant is required before calling it excessive.

| | Before | After |
|---|---:|---:|
| Findings in total | 2,601 | **2,563** |
| GHA002 findings | 346 | **319** |
| GHA002 reported at **High** | 346 | **104** |
| GHA004 reported at **Critical** | 27 | **0** |

Thirty-eight findings went away, and none of them were hidden. Twenty-seven were
grants an action in the same job cannot work without — CodeQL uploading results,
`actions/stale` editing the issues it sorts, `create-pull-request` opening the
branch it just wrote — and each is now listed as examined and accepted rather
than deleted. Eleven were checkouts whose job goes on to `git push` with the
credential the finding asked them to remove.

The larger change is the one the totals understate. GHA002 at High fell from 346
to 104: the remaining 215 did not disappear, they moved to the severity their
scope actually carries — 184 Medium, 31 Low. Every GHA004 site moved off
Critical, because none of the 27 checks out pull-request code. Removing 242
findings from the two bands a reader is meant to drop everything for, without
removing them from the report, is the whole point of the exercise.

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
| pytorch/pytorch | 151 | 151 | 758 |
| grafana/grafana | 94 | 94 | 511 |
| facebook/react | 23 | 23 | 308 |
| huggingface/transformers | 57 | 54 | 178 |
| dotnet/runtime | 25 | 25 | 141 |
| vercel/next.js | 38 | 38 | 134 |
| dotnet/aspnetcore | 21 | 21 | 113 |
| nodejs/node | 42 | 42 | 85 |
| apache/airflow | 52 | 27 | 77 |
| home-assistant/core | 13 | 10 | 63 |
| microsoft/vscode | 15 | 14 | 59 |
| hashicorp/terraform | 11 | 11 | 58 |
| prometheus/prometheus | 15 | 15 | 51 |
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

1. Download the `.yml`/`.yaml` files in `.github/workflows/` for each repository
   listed above (the GitHub contents API, no authentication needed). That
   directory only — GitHub does not treat a nested folder as workflows, and
   dotnet/runtime keeps four `.eval.yaml` files in `workflows/evals/` that
   define no jobs. Recursing picks them up and reports four parse failures that
   are not parse failures.
2. Parse each with `WorkflowParser`, evaluate every rule from
   `RuleDiscovery.All()`, count findings by rule id.
3. Numbers above reflect the repositories' default branches on 2026-08-25.
   Workflows change; a rerun will drift.

kubernetes/kubernetes was in the candidate list and excluded because it keeps
no workflows under `.github/workflows/` (CI lives in Prow).
