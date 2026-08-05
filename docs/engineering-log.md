# Engineering log

A record of the defects found in this project after it was first considered
complete, how each was found, and what now prevents it recurring.

It is kept because the defects are more instructive than the features. Every one
of them passed a build, passed a test suite, and shipped. Several were visible in
the product's own documentation without anyone noticing.

Each entry follows the same shape: what was wrong, how it surfaced, what changed,
and what would catch it next time.

---

## 1. Findings were invisible in the user interface

**What was wrong.** `WorkflowSeverity` is a domain enum. Without a converter,
`System.Text.Json` serialises it as its integer value, so the API returned
`"severity": 3`. The React client compares that field to severity names —
`finding.severity === 'Critical'` — and sorts findings by filtering against a
list of those names.

Nothing matched. The findings list rendered empty on a workflow that had
findings, the risk label read "Low" on a workflow containing high-severity ones,
and the severity counters read zero.

**How it was found.** By accident, while writing an unrelated integration test.
The test deserialised a response into a record with a `string Severity` and
failed with *"Cannot get the value of a token type 'Number' as a string"*.

**Why nothing caught it.** No test asserted the shape of a response. The tests
asserted status codes and substrings, and `Assert.Contains("GHA001", body)`
passes whether severity is a number or a name.

The symptom was also visible in a screenshot committed to the repository and
displayed in the README: a workflow with one High finding, captioned as working,
showing **Risk level Low, 0 critical, 0 high**.

**What changed.** A `JsonStringEnumConverter` is registered for the API and for
the JSON export. A test asserts the response contains `"severity":"High"` and
does not contain `"severity":3`.

**What prevents recurrence.** Assert on the wire format, not on the object you
deserialised into. A test that parses a response with your own types cannot see a
contract break, because both sides move together.

---

## 2. The exported patch could not be applied

**What was wrong.** The remediation patch is served as `text/x-diff` with a
`.patch` filename, so the implied contract is that `git apply` accepts it. It
did not, for two independent reasons:

- The diff headers named `a/workflow.yml` and `b/workflow.yml` unconditionally,
  so applying a patch for any other file failed with *"No such file or
  directory"*.
- Content was split on `\n` without accounting for the terminating newline. A
  file ending in a newline has N lines but splits into N + 1 elements, the last
  empty, so the hunk claimed a trailing blank line the file did not contain and
  git rejected it with *"patch does not apply"*.

**How it was found.** By writing a test that applies the exported patch with git
in a temporary repository and compares the result to the proposed content. It
failed on the first run, then failed again differently after the first fix.

**Why nothing caught it.** The existing assertion was
`Assert.StartsWith("@@ -1,", report.UnifiedDiff[2])`. It checked that a hunk
header was present, which is not the same as checking that the diff is valid.
The defect survived several reviews because the shape looked right.

**What changed.** Headers carry the document's own file name. The terminator is
tracked and re-expressed as the standard `\ No newline at end of file` marker
when a side lacks it. Empty content produces a `0,0` range. Two tests apply the
patch with git, covering terminated and unterminated files.

**What prevents recurrence.** When output claims to be a standard format, test it
with the tool that consumes that format. Asserting on substrings of the output
tests your idea of the format, not the format.

---

## 3. The SARIF export was not valid SARIF

**What was wrong.** Two violations of the specification, in the feature described
as *"SARIF for security tooling"*:

- `level` carried severity names — `critical`, `high`, `medium`. The
  specification defines it as a closed enumeration: `none`, `note`, `warning`,
  `error`.
- The schema key was emitted as `schema` rather than `$schema`, because `$schema`
  is not a legal C# identifier and the export was built from an anonymous type.

Every document the tool exported would have been rejected by a SARIF consumer,
including GitHub code scanning.

**How it was found.** By reading the specification while auditing the export
layer, prompted by the observation that its only test was
`Assert.Contains("2.1.0", body)`.

**Why nothing caught it.** That assertion passes on any document containing the
string `2.1.0`, including an invalid one.

**What changed.** Severities map onto the specified levels. The original severity
travels as `security-severity` on the rule, which is what GitHub code scanning
reads to bucket findings. A rule table is emitted so `ruleId` resolves through
`ruleIndex`. The export is built from records with explicit
`JsonPropertyName` attributes, so `$schema` is expressible.

A conformance test validates the schema key, every level against the enumeration,
rule and result index agreement, and that `security-severity` parses as a number.

**What prevents recurrence.** A test that asserts a format is present is not a
test that the format is correct. Validate against the specification's own rules.

---

## 4. The evidence exports omitted the evidence

**What was wrong.** The Markdown and HTML remediation reports listed a rule
identifier, a title, and whether the finding was resolved. Severity, line number,
description and recommendation were all present on the model and none reached the
page.

These are the documents the product describes as exportable security evidence.
They could not be used to triage or locate anything they reported.

**How it was found.** By reading the export code while fixing the SARIF defect.

**Why nothing caught it.** No test asserted on their content. The endpoints were
covered only by status-code checks.

**What changed.** Both exports render a findings table plus per-finding detail,
with severity, line, description and recommendation. The HTML escapes all of it.
Tests assert the severity column and the recommendation text are present, and
that no script tag survives.

---

## 5. The request rate limit was not configurable

**What was wrong.** `Operational:WorkflowRequestLimitPerMinute` was documented as
configuration. It was read into a local variable while `Program.cs` executed, so
configuration supplied later in host building never reached the limiter. The
value was fixed at whatever the base configuration said.

**How it was found.** By trying to write a test for the 429 response. The test
set the limit to two, fired three requests, and received three successes. The
override was being ignored.

**Why nothing caught it.** Nothing tested the rejection path, and with the
production default of thirty per minute it could not be reached without firing
thirty-one requests.

This was the second occurrence of the same mistake. The API security options had
the same defect and were corrected earlier, with the reason written down in a
file that is now `docs/history/C6-CONFIG-BINDING-FIX.md`. The lesson had been
recorded and not generalised.

**What changed.** The budget is bound as `OperationalOptions` and read through
`IOptionsMonitor` inside the rate-limit partition factory, matching the
correction already applied to the security options. A test sets the limit to two
and asserts the third request is rejected.

**What prevents recurrence.** Configuration read during startup is frozen at
startup. If a setting is documented as configurable, a test must change it — and
that test is what proves the wiring, not the presence of the setting.

---

## 6. Version numbers disagreed with each other

**What was wrong.** The product version appeared as a literal in five places and
had drifted to three different values:

| Location | Reported | Actual |
| --- | --- | --- |
| `/api/health` | 1.0.0 | 1.0.1 |
| SARIF tool descriptor | 1.0.0 | 1.0.1 |
| Two GitHub `User-Agent` headers | 0.4.0 | 1.0.1 |
| Application header | v1.0 | 1.0.1 |

The SARIF descriptor is the one that matters most: it travels inside exported
security evidence, where the version of the tool that produced a finding is part
of the record.

Separately, the `v1.0.1` tag pointed at a commit whose version markers read
`1.0.0`, because the tag was cut before the version was bumped.

**How it was found.** By grepping for version literals while investigating why a
screenshot showed an old version in the application header.

**What changed.** `ProductInfo` reads the informational version from the
assembly, so `Directory.Build.props` is the only place a version is written on
the server side. The client reads `package.json` through a Vite define.
`verify-release-package.ps1` holds `Directory.Build.props`, `package.json`,
`package-lock.json` and any release tag equal, and CI runs it on tag pushes.

**What prevents recurrence.** One source, derived everywhere else. A version
written in two places is a version that will eventually disagree with itself.

---

## 7. Rules matched text rather than structure

**What was wrong.** The permissions rule matched any line ending in `: write`
across the whole file. A comment reading `# contents: write` produced a finding.
So did an unrelated input such as `mode: write` under a step's `with:` block.

The parser was line-oriented throughout, which also meant `permissions:
{contents: write}` in flow style was missed entirely, and a quoted `'on':` key —
written that way precisely to stop YAML 1.1 resolving `on` to the boolean `true`
— was invisible to a prefix match.

**How it was found.** By reading the rules against the YAML specification rather
than against the examples they were written for.

**What changed.** Document structure is read with a real YAML parser, and the
structural rules read that. The line model remains for content inside block
scalars, which YAML models as a single opaque scalar, and for line-indexed
patching. Structure answers questions about relationships; lines answer questions
about content.

**What prevents recurrence.** A security tool that reports findings has to be
right about what it is reading. Indentation arithmetic agrees with YAML often
enough to look correct and fails quietly when it does not.

---

## 8. The analyser did not detect script injection

**What was wrong.** Nothing detected `${{ github.event.* }}` interpolated into a
`run:` body — the most exploited GitHub Actions vulnerability class in the wild.

**How it was found.** By comparing the rule set against the actual GitHub Actions
threat landscape rather than against itself.

**What changed.** GHA005 reports attacker-controllable expressions in script
bodies. Adding it required a parser change: block scalar content is deliberately
withheld from the line model, because treating shell as YAML caused the false
positives described above. Script bodies are now captured separately, so the
existing rules are unaffected.

Three more followed from the same exercise: GHA006 for persisted checkout
credentials, GHA007 for a privileged trigger checking out pull-request code, and
later GHA008 to GHA011.

**A correction worth recording.** It was initially claimed that this rule would
have flagged a pattern in this repository's own CI. It would not. The expressions
there were `github.sha` and two commit SHAs — GitHub-controlled and not
attacker-settable. What was present was the pattern with safe values, not an
exploitable injection, and the rule correctly stays quiet. Precision is the point
of a deterministic analyser, and an overstated claim about one's own tool is
worse than a missing rule.

---

## 9. The repository protection gate checked nothing

**What was wrong.** `check-repository.ps1` iterated `git ls-files 2>$null` to
find forbidden files. The project was not a git repository at the time, so the
command produced nothing, the loop found no violations, and the script printed
**"Repository protection check passed."** in green.

The gate whose entire purpose was proving no secrets were tracked had never
examined anything.

**How it was found.** By running it and noticing it passed instantly on a
directory with no `.git` in it.

**What changed.** The script fails if it is not inside a git repository, and
fails if no tracked files are found.

**What prevents recurrence.** A check that cannot fail is not a check. When a
gate passes, confirm it passed because the condition held, not because the
condition could not be evaluated.

---

## 10. Log entries could be forged by a request

**What was wrong.** The request path is chosen by the caller and reached three
loggers verbatim. A path containing a carriage return or line feed splits one log
entry into several, so a caller could fabricate lines that appear to have been
emitted by the application.

**How it was found.** By CodeQL, on its first run against the repository, once
the project was public and code scanning became available.

**What changed.** Request-supplied values are sanitised before logging. Control
characters are replaced rather than removed, so a request that attempted the
injection remains visible as having done so, and long values are truncated.

**What prevents recurrence.** Structured logging does not neutralise input on its
own, because most sinks render the message template into a single line of text.

---

## 11. The smoke suite protected nothing

**What was wrong.** Twenty-five end-to-end checks existed and ran only when
someone chose to run them. The release script ended by printing *"start the API
before running smoke tests"*.

**What changed.** The script starts and stops the API itself, runs as part of the
local gate, and runs in CI. It forces Mock mode and disables GitHub so it never
spends credit or reaches the network.

**Why it is worth running despite overlap.** Most of what it asserts is also
asserted by the integration tests. What is not duplicated is that the application
starts. The integration tests boot it through `WebApplicationFactory` with the
environment set to Testing and configuration supplied in memory, so nothing in
them exercises `appsettings.json`, `ValidateOnStart`, the scenario files being
copied to the output directory, or HTTPS redirection.

Every one of those tests can pass on an application that will not run.

---

## 12. The pipeline could not run the actions it was pinned to

**What was wrong.** The first deployment workflow failed with `startup_failure`
and no log at all — no job ran, so there was nothing to log. The workflow file
was valid: it parsed, `actionlint` passed it clean, every pinned SHA resolved and
was reachable from a tag or branch, and GitHub listed the workflow as `active`.

The repository's own Actions policy was blocking it. `allowed_actions` was set to
`selected`, permitting GitHub-owned actions plus one entry for Gitleaks.
`azure/login`, `azure/webapps-deploy` and `Azure/static-web-apps-deploy` were not
on the list, and an action outside the allowlist is refused before any job
starts.

**How it was found.** By bisection, after the file itself had been exonerated
several times over. A probe workflow was cut down to one job and pushed, then
grown a step at a time. Everything passed until `azure/login` was added, and
that step failed identically every time.

The first theory was wrong: `azure/login@v2.3.1` declares a `post-if` expression,
which looked like the sort of thing a workflow parser might reject. Pinning back
to v2.1.1, which has no `post-if`, failed exactly the same way — which is what
ruled the file out and pointed at the repository instead.

**Why nothing caught it.** Nothing could. The allowlist is repository
configuration, not a file in the tree, so no linter, no test and no review of the
diff can see it. The workflow is correct; the environment refuses it. The failure
surfaces only against the repository that carries the policy.

It is also the control working as designed. A third-party action that can
authenticate to an Azure subscription should require a deliberate decision rather
than arriving with a merged pull request.

**What changed.** The three Azure actions were added to `patterns_allowed`, each
pinned to a commit, which `sha_pinning_required` independently enforces.

**What prevents recurrence.** Knowing the failure mode is the prevention: a
`startup_failure` with no log, on a workflow that lints clean, means the
repository refused something the file asked for. Check
`/actions/permissions/selected-actions` before reading the YAML again.

---

## 13. The deployment identity did not match the identity presented

**What was wrong.** `provision-azure.ps1` registered a federated credential with
the subject `repo:bgard68/DevSecOpsSentinel:ref:refs/heads/main`. GitHub presents
`repo:bgard68@30295154/DevSecOpsSentinel@1322411111:ref:refs/heads/main` — the
owner and repository carry immutable numeric ids. The two never match, so every
deployment failed to authenticate.

**How it was found.** Entra answers a mismatch with `AADSTS700213: No matching
federated identity record found for presented assertion subject`, followed by the
subject it received. The error names the symptom and not the cause, and the
constructed subject looks entirely reasonable next to it. What settled it was
that the workflow log prints the subject GitHub actually sent, immediately above
the error.

**Why nothing caught it.** The subject was assembled from owner and repository
names, which is what the documentation showed when the script was written. A
value you construct yourself is the last thing you check, because it looks
correct — it is exactly what you meant to write.

The credential check made it worse: it matched on the credential's **name**, so
a credential with a wrong subject sat there looking present and correct, and
re-running the script could never repair it.

**What changed.** The prefix is now read from
`repos/{owner}/{repo}/actions/oidc/customization/sub` rather than assembled, so
the format stays GitHub's to decide. The existence check compares the subject and
updates in place when it differs.

**What prevents recurrence.** Ask the system for the value it will send. Any
identifier that another party generates — subjects, audiences, issuer URLs — is
theirs to change, and a local reconstruction of it is a copy that will eventually
drift.

---

## 14. A successful deployment was reported as a failure

**What was wrong.** The deploy workflow ran the smoke suite immediately after
pushing the package. App Service recycles the app after a deployment, and on the
free tier the restart and cold start together take most of a minute. The smoke
test asserted against an app that had not finished starting, got a 404, and
failed a deployment that had in fact worked — the same endpoints answered
correctly a minute later.

**How it was found.** By checking the deployed API by hand after the workflow
went red, and finding it healthy.

**Why nothing caught it.** The race cannot occur locally, where the API is
already running before the smoke test is invoked. It requires a real deployment
against a platform that restarts, and the free tier makes the window wide enough
to lose reliably. A sibling repository had already hit this and its script
carries a comment saying so; the knowledge existed and was not transferred.

**What changed.** A wait step polls `/api/health/live` until it answers before
the smoke test runs, so the suite keeps asserting rather than waiting.

**What prevents recurrence.** Separate waiting from asserting. A check that
retries until success cannot distinguish "not ready yet" from "broken", and one
that does not retry cannot distinguish them either — so the wait belongs in front
of the assertion, not inside it.

---

## 15. The smoke suite required the API documentation to be exposed

**What was wrong.** Two of the twenty-five checks asserted that
`/openapi/v1.json` and `/scalar` return 200. Those endpoints are served only in
Development and Testing; on any deployment that authenticates, they correctly
return 401. So the suite demanded the opposite of the property the application
was built to hold, and would have failed against every correct production
deployment.

It also asked the wrong question about the key. The guard threw only when
`required` was true, and `Public` mode reports `required: false` — so a run
against a public deployment would proceed without a key and then fail on the
GitHub checks, which still need one.

**How it was found.** The first deployment whose smoke suite ran to completion.
Every earlier run had died before reaching these checks — first on a workflow
that would not start, then on an application that had not finished restarting.
Twenty-three passed, two failed, and both failures were the suite being wrong.

**Why nothing caught it.** The suite is only ever run locally before a
deployment exists, and locally the environment is Development, where 200 is the
right answer. The assertion was true everywhere it had been executed and false
everywhere it mattered.

**What changed.** The expectation is derived from the reported mode: 200 when
`Disabled` — which is legal only in Development and Testing — and 401 otherwise.
The check now asserts that the documentation is **not** reachable on a deployment
that authenticates, which is worth confirming. The key guard asks whether the
deployment uses a key at all rather than whether one is required to enter.

**A second time, for the same reason.** Deriving the expectation from the mode
fixed the environment half and left the layer half: `Required` produces 401,
because the API-key middleware refuses before routing, and `Public` produces 404,
because the middleware allows it through and the endpoints are simply not mapped
outside Development. The first deployment in `Public` mode failed on a property
that held perfectly well. The check now accepts either, because what is being
asserted is that the documentation is unreachable — not which component said no.

**What prevents recurrence.** A check whose expected value is a constant is
asserting something about one environment. When the property under test is
conditional, the expectation has to be derived from the same condition — or the
test passes where it does not matter and fails where it does. And when a property
can be enforced at more than one layer, asserting a single status code asserts
the layer rather than the property.

---

## 16. A refused privileged call emptied the public workspace

**What was wrong.** The client loaded its three start-up resources together:

```ts
Promise.all([getScenarios(), getAiStatus(), getGitHubStatus()])
```

`Promise.all` rejects as soon as any input rejects, and discards the results of
the ones that succeeded. Opening the scanner to anonymous visitors made
`/api/github/status` answer 401 for them — which is the design, not a fault — so
the batch rejected, the scenarios that had already arrived were thrown away, and
the scenario dropdown rendered empty against an API that was working correctly.

The visible symptom pointed at the wrong thing entirely: an empty dropdown and a
console 401 look like the scanner endpoints are unreachable.

**How it was found.** By loading the deployed site and asking the page itself
what it could see. A `fetch` to `/api/scenarios` from the page's own origin
returned 200 with seven scenarios while the dropdown next to it was empty —
which ruled out CORS, the bundle, the deployment and the API in one step, and
left only the client's own handling.

**Why nothing caught it.** Every existing client test served all three endpoints
successfully, because until this release every deployment either required a key
for all of them or required none. The combination that breaks it — a caller who
is authorised for some endpoints and refused others — did not exist before the
mode that created it, and no test described it.

**What changed.** `Promise.allSettled`, with the results separated by
consequence: scenarios failing is a real error and still throws, while the two
status badges degrade quietly. A test renders the client against a 401 from
`/api/github/status` and asserts the scenario list is still populated.

**What prevents recurrence.** `Promise.all` couples the failure of every call to
the success of all the others. That is right for things that genuinely stand or
fall together, and wrong for a page assembling independent pieces — where one
refusal should cost you that piece and nothing else. Partial authorisation makes
the difference visible; uniform authorisation hides it.

---

## 17. A rejected key was indistinguishable from an accepted one

**What was wrong.** Entering the access key stored whatever was typed and
switched the interface to its unlocked state without ever asking the API whether
the key worked. A wrong key produced a header reading "Lock API", as though it
had been accepted, and the only symptom was the GitHub panel quietly continuing
to say unavailable — which reads as the integration being down, not as the key
being wrong.

**How it was found.** By pasting the key into the deployed site and watching it
appear to work while GitHub stayed unavailable.

**Why nothing caught it.** Every client test supplied a working key, so the
rejection path had no coverage. It was also made worse an hour earlier: the fix
for defect 16 replaced `Promise.all` with `allSettled` so that a 401 from the
privileged endpoint would not empty the workspace — correct for an anonymous
visitor, and it turned the same 401 into silence for someone who had just
supplied a key. Loud in the wrong case became quiet in both.

**What changed.** The key is verified before it is accepted: a privileged
endpoint is called and the status code inspected, so a 401 rejects the key,
clears it, and says so. The status code is read rather than the body, because a
GitHub integration that is merely disabled still answers 200 to a caller holding
a valid key — the question is whether the key was accepted, not whether GitHub is
working. Two tests cover it: a key the API refuses is not stored and reports
itself, and a key it accepts connects.

**What prevents recurrence.** When a change stops a failure being fatal, check
what else was relying on it being noticed. `allSettled` was the right call for
the anonymous case and removed the only signal the authenticated case had. A
failure that is expected in one state and diagnostic in another has to be
distinguished by state, not swallowed for both.

---

## 18. A severity no rule could produce

**What was wrong.** `WorkflowSeverity` defines Low, Medium, High and Critical,
and its own summary states that every member is produced by at least one rule.
No rule produced Low. The client rendered an ordering category that could never
fill, and every export carried a level that never appeared.

The cause was a mis-calibration rather than an oversight. GHA003 — a job with no
`timeout-minutes` — sat at Medium alongside a token left readable on the runner
(GHA006) and a permission grant nobody can see (GHA009). A missing timeout
consumes minutes and, on a self-hosted runner, occupies it; it exposes nothing.
Rating it with those flattened the distinction between *this wastes resources*
and *this exposes something*, which is the distinction a severity is for.

**How it was found.** By running all seven bundled scenarios and tabulating the
severities they produce, to answer a question about what the demonstration
covers. Critical, High and Medium all appeared. Low did not appear anywhere.

**Why nothing caught it.** Nothing asserted the invariant the enum documents,
and no test asserted any rule's severity at all. The same defect had already been
fixed once, by deleting `Informational` — the fix was applied to the instance and
the rule was never written down.

**What changed.** GHA003 is Low, which both fills the scale and rates it more
honestly. Three invariants are now asserted: every severity is produced by some
rule, every rule declares a severity the scale defines, and rule identifiers are
unique. The rule list they run against is shared with the self-scan rather than
copied, because a private copy of a list is a list that silently goes stale.

**What prevents recurrence.** An invariant stated in a comment is a wish.
`WorkflowSeverity` had described this property in its own summary for as long as
it had been false. If it is worth writing in a doc comment, it is worth a test —
otherwise the comment documents an intention and the code does something else.

---

## Patterns

Reading the eighteen together, six things recur.

**A test that cannot fail proves nothing.** The protection gate that ran against
no files, the SARIF assertion that matched any document containing `2.1.0`, the
rate limit that could not be exercised. Each was counted as coverage.

**Assert on the contract, not on your own types.** The severity defect survived
because tests deserialised responses using the same records the server
serialised. Both sides moved together and the break was invisible.

**Output claiming to be a standard format must be checked by that format's
tools.** The patch and SARIF defects were both found this way and neither would
have been found otherwise.

**A lesson written down is not a lesson generalised.** The configuration binding
mistake was diagnosed, fixed, and documented — then repeated in a second place
that nobody thought to check. The post-deploy race is the same shape across
repositories: a sibling project had hit it and left a comment explaining it, and
this one hit it anyway.

**A fix can take away the signal something else was relying on.** Making a
refused privileged call non-fatal was right for an anonymous visitor and, in the
same stroke, made a rejected key silent for someone who had just supplied one.
Defect 17 was created by the fix for defect 16, within the hour. When a change
stops a failure being noticed, the question is who else was noticing it.

**Some defects are not in the code.** Several of the last few surfaced only when the
project first ran somewhere real. An allowlist that is repository configuration,
a subject string another system generates, a platform that restarts after a
deployment — none is visible in the tree, so no linter, test or review of the
diff could have found them. The first deployment is itself a test, and it is the
only one that runs the environment.
