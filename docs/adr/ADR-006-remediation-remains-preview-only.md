# ADR-006: Remediation remains preview-only in Phase E

## Decision

Phase E generates, validates, compares, and exports remediation content but does not write to GitHub.

## Rationale

Separating analysis and remediation preview from repository mutation preserves least privilege, makes review explicit, and prevents AI or deterministic automation from silently changing source control.

## Consequences

The GitHub App remains read-only. Repository write permissions and pull-request creation are outside Phase E.
