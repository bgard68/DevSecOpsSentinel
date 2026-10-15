# Maturity and review coverage

What this project is ready for, what it is not, and — the part usually left out —
which of its code has actually been read closely by someone looking for defects.

Assessed against solo-built demonstration projects of this kind, it stands near
the top of that class. Assessed as a multi-tenant production service, it does
not qualify, for the three reasons under [Ceilings](#ceilings). The difference is
those ceilings rather than the engineering, and each is deliberate and recorded.

This page is kept current because the alternative is a reader inferring maturity
from how confident the other documents sound.

---

## What is hardened

These are load-bearing and covered by tests that fail when the behaviour breaks:

- Deterministic rules are the only source of truth
  ([ADR-001](adr/ADR-001-deterministic-rules.md)), and the model cannot invent,
  drop, rename or re-severity a finding
  ([ADR-003](adr/ADR-003-ai-is-not-source-of-truth.md),
  [ai-containment.md](architecture/ai-containment.md)).
- The GitHub App is read-only, and an application-level allowlist is a second,
  independent boundary ([ADR-004](adr/ADR-004-github-app-read-only.md)). An
  allowlist entry that could never match is now refused at startup rather than
  appearing to permit something.
- Remediation is a preview; nothing writes to a repository
  ([ADR-006](adr/ADR-006-remediation-remains-preview-only.md)). A patch is
  declared valid only if it re-parses, preserves the job and trigger set, and
  increases no rule's finding count.
- A patch that fails validation is not offered as an improvement at all, so a
  rejected patch cannot be reported as a risk reduction.
- Resolution is recorded per finding by the patch that edited it, not inferred
  from surviving rule ids, so two findings of one rule are told apart.
- The unified diff is bounded in memory. See
  [program-flow.md](architecture/program-flow.md#the-diff-is-bounded) — this
  matters because the deployment target has 1 GB for the whole host.
- Configuration is validated on start for the `Security`, `OpenAI` and `GitHub`
  sections, and a value the application accepts is a value it honours rather
  than one it silently clamps.
- Operational basics: partitioned rate limiting, security headers, RFC 7807
  problem documents, correlation IDs, and logs that cannot be forged by a
  request-supplied path.

---

## Ceilings

Three things stop this being a production service for more than one operator.
All three are intentional, and none is a defect to be fixed in passing.

**1. Authentication is single-operator.** A shared API key, held in browser
`sessionStorage` for the tab. Suitable for a private demonstration, and
unsuitable for anything multi-user — a key cannot express who someone is, so
there is nothing to authorise per user and nothing to revoke individually. OIDC
with per-user authorisation is the answer and it is a project, not a patch. See
[SECURITY.md](../SECURITY.md) and [configuration.md](configuration.md).

**2. Nothing is stored.** No history, no saved scans, no accounts. Each would
need its own threat model and new permissions, so each is absent rather than
half-built. See
[architecture/README.md](architecture/README.md#deliberate-exclusions).

**3. Observability is logs and correlation IDs.** No traces, no metrics, no
SLOs, no alerting. Partly a deliberate trade: on an App Service free tier the
whole host has 60 CPU-minutes per day, and an exporter spends that budget on
telemetry instead of on serving. It is the right call at this size and the wrong
one at any larger size.

---

## Review coverage

Not all of this code has been examined to the same depth. Stating where the line
falls is more useful than implying it falls everywhere.

| Reviewed closely for defects | Not reviewed line by line |
| --- | --- |
| Application and Domain layers | `WorkflowParser` |
| The composition root | `YamlWorkflowStructureReader` |
| Workflow and status endpoints | GitHub readers, JWT factory, reference resolver |
| Remediation report and the export renderers | `PublicRepositoryScanner` internals |
| `WorkflowPatchGenerator` and the fix strategies | The middleware chain |
| `IWorkflowSecurityRule` and the three auto-fixable rules | Eight of the eleven rules |
| AI provider selection and the options plumbing | Most of the React client |

### Why the line matters

Three defects that reported untrue results were found in the reviewed column —
[entries 31, 32 and 33](engineering-log.md) of the engineering log. All three had
passed a full suite of 493 tests, and all three survived for the same reason:
every test used **one finding per rule**. With one of a thing, inferring an
outcome from its rule id is correct, and pairing two lists by index is correct.
The suite agreed with the code for the only shape it ever examined.

That blind spot is a property of how the tests were written, not of the code
they covered, so there is no reason to assume it stops at the edge of the
reviewed column. The unreviewed column has not been checked for it.

As the log puts it: a test suite that only ever sees one of a thing cannot see a
bug about telling two of them apart.

---

## What would change this assessment

Two things, in order. Neither is polish.

1. **Review the remaining code to the same depth**, specifically hunting the
   single-of-a-thing blind spot: anywhere an outcome is attributed by category
   rather than by identity, or two collections are assumed to correspond.
2. **OIDC with per-user authorisation**, which removes ceiling 1 and makes
   ceilings 2 and 3 worth revisiting rather than defending.
