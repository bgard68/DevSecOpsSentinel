# Phase C UI polish

The final Phase C dashboard presents the deterministic analyzer and AI advisor as a single product experience.

## Layout

- Product header with API, AI mode, and cost-safety status.
- Security-boundary strip explaining deterministic authority, explicit AI opt-in, and sanitization.
- Sticky workflow input workspace on desktop and a single-column responsive layout on smaller screens.
- Risk, finding, auto-fix, and patch-validation metrics.
- Tabbed results for deterministic findings, workflow comparison, and AI advice.

## Deterministic findings

Findings remain authoritative and display stable rule IDs, severity, source location, auto-fix availability, and remediation guidance.

## AI advisor

The advisor is visibly labeled as advisory. It cannot invent findings, change severity, or apply code. Mock mode remains the default and consumes no API credits.

## Workflow comparison

Original and proposed YAML are shown in dedicated scrollable panels with distinct visual treatment and keyboard focus support.

## Accessibility and responsive behavior

- Explicit labels and accessible result navigation.
- Visible keyboard focus styles.
- Reduced-motion support.
- Responsive metrics, workflow panels, and advisor cards.
