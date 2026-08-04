# DevSecOps Sentinel v1.0.0

DevSecOps Sentinel v1.0.0 delivers a complete read-only GitHub Actions security-analysis workflow.

## Highlights

- Analyze embedded examples or real workflows retrieved through a read-only GitHub App.
- Keep deterministic rules authoritative while using OpenAI for optional explanations.
- Preview validated remediations, compare workflows, and quantify risk reduction.
- Export findings and remediation evidence in multiple formats.
- Run comprehensive local release gates with one PowerShell command.

## Security posture

This release intentionally contains no GitHub write operations. AI output is advisory, repository access is allowlisted, credentials remain server-side, and proposed fixes are re-analyzed before being marked valid.

## Known limitations

- No branch, commit, pull-request, or merge creation
- No scheduled or background repository scanning
- No durable result history
- No browser-level end-to-end test suite
