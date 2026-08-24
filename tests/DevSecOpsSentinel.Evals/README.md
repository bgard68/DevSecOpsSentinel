# Evals

Scores the deterministic scanner against a corpus of workflow files whose correct findings
are written down independently of what the scanner currently returns.

## Why this exists separately from the unit tests

`SecurityRuleTests` asks whether a rule fires on input built to make it fire. That catches a
broken rule. It does not catch a rule firing on input it should ignore, because no test
constructs that input — the fixture and the assertion are written together, so they agree.

The corpus is written the other way round. Each `.yml` in `Corpus/` is a workflow; each entry
in `GoldenCorpus.cs` states the rule ids a correct scan produces, derived from reading the
rules' trigger conditions rather than from running them. When the two disagree, the eval says
which direction: `missed` is a blind spot, `spurious` is noise. They are different defects and
deserve different responses.

Most fixtures are narrowed to one rule by applying every other rule's suppression — actions
pinned to a SHA, permissions declared, timeout set, credentials not persisted. Two compound
fixtures are kept deliberately, because real workflows stack weaknesses and a scanner that
only sees isolated faults is not being asked a hard question.

## What it found

On its first run the corpus disagreed on `inherited-secrets.yml`: the scanner reported GHA003
against a job that calls a reusable workflow. GitHub does not accept `timeout-minutes` on such
a job — the supported keys are `uses`, `with`, `secrets`, `needs`, `if`, `permissions`,
`strategy` and `concurrency` — so the finding asked for a change that makes the workflow
invalid. Because GHA003 is marked automatically fixable, the remediation preview would have
offered exactly that patch. `MissingTimeoutRule` now skips reusable-workflow callers.

## The replay corpus

`Corpus/` measures the scanner. `Responses/` measures what happens to a model reply.

Each file there is a reply in the shape the provider returns, paired in `ReplayCorpus.cs`
with the workflow it answers and the verdict the containment gate must reach. Replies are
data on disk, so a reply captured from the live provider can be dropped in beside the
authored ones and scored by the same code.

The authored ones cover what a live capture will not produce on demand. `prompt-injection.yml`
carries comments addressed at the model, telling it to report an invented rule and hide the
real one — workflow content comes from whatever repository is being scanned, so an attacker
writes that text. Three replies answer it: one that resists, one that obeys, and one that
partially obeys by dropping the real finding while inventing nothing.

The point is not that the model resists. It may not. The point is that a reply obeying the
injection is rejected anyway, because a rule id the scanner never produced cannot survive the
gate. That is what makes the defence a property of the system rather than of the model.

## Cost

Offline. No API key, no network, no spend, so it runs on every push rather than behind a
decision about whether today is worth the credits. The model layer is measured separately: its
containment gate is pinned by `AiContainmentTests`, which is also offline.

## Capturing a real reply

The corpus scores replies; it does not make them. To add one from the live provider, run a
live analysis, save the raw JSON to `Responses/<workflow>.<label>.json`, and declare it in
`ReplayCorpus.cs` with the verdict you expect. The spend is one call, once — from then on the
reply is scored offline on every push, forever.

An undeclared file in `Responses/` fails the eval, so a captured reply cannot sit there
looking like coverage while contributing nothing.

## Adding a fixture

1. Write the workflow in `Corpus/`, suppressing every rule you are not targeting.
2. Add a `CorpusEntry` naming the rule ids a correct scan returns, and why the file exists.
3. Run the eval. If it disagrees, decide which side is wrong before changing either.

Two guards keep the corpus honest: a declared entry with no file fails, and a file nobody
declared fails. A rule registered in Infrastructure with no fixture also fails, so a new rule
cannot ship unmeasured — the rule list is discovered by reflection, never hand-copied.

`scoreboard.md` is written to the test output directory on each run.
