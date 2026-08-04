# Portfolio Walkthrough and Engineering Assessment

## Executive assessment

DevSecOps Sentinel is stronger than a typical CRUD portfolio application because it demonstrates architecture, security boundaries, external-service integration, deterministic analysis, AI augmentation, automated validation, and operational readiness in one coherent product.

### Architecture — A

The layers have clear responsibilities. Domain and application logic remain independent of HTTP, GitHub, and OpenAI concerns. SOLID, dependency inversion, and single responsibility are used where they materially improve testability and replaceability rather than as checklist patterns.

### Security — A

The strongest decision is the trust model:

- GitHub access uses a read-only GitHub App instead of a personal access token.
- Repository access requires both installation permission and an explicit application allowlist.
- OpenAI is advisory and cannot originate findings or change severity.
- Proposed remediations are re-analyzed before being presented as valid.
- Secrets remain outside source control.

### Testing — A-

The project includes domain, application, infrastructure, API integration, React, package-audit, repository-protection, and PowerShell smoke-test coverage. A future browser-level Playwright suite would be a useful addition but is not required for this release.

### Maintainability — A

Central Package Management, deterministic builds, warnings-as-errors, locked frontend dependencies, toolchain verification, and one-command release gates improve reproducibility and reduce onboarding friction.

### AI integration — A

The AI integration is defensible because it augments deterministic findings instead of replacing security logic. Live and Mock modes support safe demos, controlled costs, and repeatable tests.

### Portfolio value — A+

The application provides strong interview material around Clean Architecture, GitHub App authentication, secret handling, deterministic versus probabilistic systems, risk reduction, structured exports, accessibility, testing strategy, and operational hardening.

## Key engineering decisions

### Deterministic findings are authoritative

An LLM can explain a finding but cannot decide that a rule exists, change severity, or claim a patch was applied. This reduces hallucination risk and keeps results reproducible.

### GitHub remains read-only

The application retrieves real workflow files but cannot modify repositories. This creates a useful product while keeping permissions and threat surface small.

### Remediation is validated, not merely generated

The proposed workflow is re-run through the same rule engine. The UI reports which findings were resolved, which remain, and whether the patch is valid.

### Mock mode is a product feature

Mock mode makes tests, demos, and local onboarding independent of API credits and provider availability. Live mode is an explicit server-side override.

## Trade-offs

- No database: the current product does not require durable state; adding persistence would create operational cost with low payoff.
- No MediatR: direct application services are clearer at this scale and avoid indirection without benefit.
- No EF Core: there is no persistence requirement. Dapper would be considered only if a later phase introduces a relational store.
- No autonomous repository writes: human review and stronger authentication are required before write permissions would be responsible.

## Interview discussion prompts

- Why is deterministic analysis preferable to LLM-only security review?
- How does GitHub App installation authentication work?
- Why use two repository-access boundaries?
- How are provider failures handled without losing deterministic results?
- How are proposed remediations validated?
- Which SOLID principles were used, and which patterns were intentionally avoided?
- How do Central Package Management and frontend toolchain verification improve reproducibility?

## Recommended screenshots

1. `docs/assets/screenshots/01-connected-dashboard.png` — full connected state.
2. `docs/assets/screenshots/02-live-ai-vulnerable-workflow.png` — deterministic finding plus live AI explanation.
3. `docs/assets/screenshots/03-live-ai-safe-workflow.png` — zero findings and restrained AI explanation.
