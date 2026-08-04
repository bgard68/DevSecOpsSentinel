# ADR-003: AI is not the source of truth

## Decision

Deterministic C# rules remain authoritative. OpenAI explains known findings but cannot create rule IDs, alter severity, or certify patch validity.

## Rationale

Security decisions must be reproducible, testable, and available when the provider is unavailable. AI adds communication value without weakening the trust boundary.
