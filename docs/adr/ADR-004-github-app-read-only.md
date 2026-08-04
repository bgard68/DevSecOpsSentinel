# ADR-004: Use a read-only GitHub App

## Decision

Use a GitHub App with read-only repository contents permission and selected-repository installation scope.

## Rationale

A GitHub App provides fine-grained permissions, short-lived installation tokens, and a narrower security boundary than a personal access token.

## Consequences

Phase D.3 can read and analyze workflows from the sandbox repository. It cannot modify repository content or create pull requests.
