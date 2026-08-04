# Secure remediation design

The remediation engine consumes the existing deterministic analysis result and its validated patch preview. It then re-runs the deterministic scanner against the proposed content. This makes the risk-reduction summary evidence-based rather than inferred by AI.

OpenAI may explain a finding, but it cannot create findings, change severity, mark a finding resolved, or apply a patch.

## Exports

- Markdown: human-readable review report.
- JSON: full structured report.
- SARIF: security tooling interoperability.
- HTML: printable report; use the browser print command to save as PDF.
- Diff: patch-format remediation preview.

All exports are generated from deterministic results and contain no GitHub credentials or OpenAI keys.
