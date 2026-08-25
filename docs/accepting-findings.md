# Accepting a finding

Some findings are correct and still acceptable. Deleting a workflow run needs
`actions: write`, and GitHub offers no narrower grant — so the finding is right,
the remediation is impossible, and somebody has to decide the risk is worth it.

A scanner with nowhere to put that decision has two failure modes: the finding
reports forever, or the reader learns to skim past it. Both end in the same
place.

## The syntax

```yaml
permissions:
  # sentinel:accept GHA002 - deleting a workflow run has no narrower grant
  actions: write
```

The comment may sit on its own line above what it accepts, or trail it:

```yaml
      actions: write # sentinel:accept GHA002 - no narrower grant exists
```

The separator between the rule id and the reason is optional; `-`, `—`, `:` and
plain whitespace all read the same way.

## Why it lives in the workflow

The obvious design is a separate file — `.sentinel.yml` listing file, line, rule
and reason. It is the wrong one:

- **Line numbers drift.** The first edit to the workflow silently repoints every
  entry at whatever moved into that position.
- **The reason ends up far from what it explains.** A reader looking at
  `actions: write` has no indication that anyone ever thought about it.
- **The file outlives the code.** Nothing deletes an entry when the workflow
  changes underneath it.

A comment is deleted by the same edit that deletes the line it annotates, and a
reviewer sees it appear in the diff beside the thing it waves away.

It also fits the constraints this project already accepted: analysis is
read-only and needs no sign-in, so there is no account to store a decision
against. It has to live in the repository being read.

## What it refuses to do

The mechanism is a judgement recorder. Three refusals are what keep it from
becoming a mute button.

### An acceptance with no reason is ignored

```yaml
# sentinel:accept GHA002
actions: write
```

The finding still reports, and the directive's own line is reported as well.

A bare marker records that somebody wanted the finding gone. It does not record
that anybody considered it, and the difference is the entire value. Writing the
sentence is the work; the comment is only where the work is kept.

### An acceptance covers one line and one rule

Acceptance is matched on rule **and** line together. Accepting `GHA002` on one
grant does not quietly accept a second `GHA002` elsewhere in the same file, and
does not accept `GHA006` on the same line.

A file-wide or rule-wide switch would let one considered decision silence an
arbitrary number of unconsidered ones.

### An acceptance that outlived its finding is reported

If a grant is accepted and later removed, the comment is still sitting there —
now claiming that somebody considered a problem which is no longer present. It
reads as considered when nothing considered it, and the next reader has no way
to tell the difference.

That is reported as **GHA012**, against the acceptance mechanism rather than
against any workflow rule, so it cannot be mistaken for the finding it refers
to.

Every suppression list accumulates these. Reporting them is what stops this one
rotting into decoration.

## Nothing disappears

An accepted finding is not deleted. It moves into **Reviewed and accepted**,
keeping its original severity and gaining the stated reason, and the summary
reports both counts:

```
prune-runs.yml — Clean · 0 findings

  REVIEWED AND ACCEPTED                                            1
  ✓ Workflow grants excessive token permissions - accepted   GHA002  Line 51
    accepted by author
    deleting a workflow run has no narrower grant (accepted in the
    workflow, line 46; severity was High)
```

A suppressed Critical is quiet, never invisible.

The interface distinguishes two kinds of acceptance, because they are different
claims and only one of them can be wrong about the risk:

| Badge | Meaning |
| --- | --- |
| `required by an action` | Established by the rule. `github/codeql-action/analyze` cannot upload results without `security-events: write` — a documented fact, not a judgement. |
| `accepted by author` | A person read the finding and decided the risk was acceptable, and said why. |

## This repository uses it

`prune-runs.yml` is the only workflow here that carries an acceptance, and the
reason states the cost rather than waving it away — `actions: write` also
permits deleting any run in the repository, so the job can destroy the audit
trail it exists to keep readable.

Two acceptances that used to live beside it were deleted rather than migrated:
`codeql.yml` and `dependency-review.yml` are now recognised by the rule itself,
which is a better answer than a human accepting the same thing on every
repository that uses those actions. See
[architecture/rules.md](architecture/rules.md#establishing-need).

`RepositoryWorkflowsTests` measures this repository the way the product reports,
acceptances included, and fails on an acceptance of its own that is stale or
unexplained.
