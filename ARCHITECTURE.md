# Architecture

## Overview

DevSecOps Sentinel follows Clean Architecture pragmatically. Dependencies point inward toward stable application and domain contracts, while GitHub, OpenAI, export formatting, and HTTP concerns remain at the edges.

```mermaid
flowchart TB
    subgraph Presentation
      WEB[React + TypeScript]
      API[ASP.NET Core Minimal APIs]
    end
    subgraph Application
      ANALYZE[Workflow analysis orchestration]
      EXPLAIN[AI explanation orchestration]
      REMEDIATE[Remediation and risk reduction]
    end
    subgraph Domain
      RULES[Deterministic security rules]
      MODELS[Findings, severity, analysis models]
    end
    subgraph Infrastructure
      GITHUB[GitHub App reader]
      OPENAI[OpenAI provider]
      EXPORTS[Export adapters]
    end
    WEB --> API
    API --> ANALYZE
    API --> EXPLAIN
    API --> REMEDIATE
    ANALYZE --> RULES
    REMEDIATE --> RULES
    EXPLAIN --> OPENAI
    ANALYZE --> GITHUB
    REMEDIATE --> EXPORTS
    RULES --> MODELS
```

## Request pipeline

```mermaid
sequenceDiagram
    participant U as User
    participant W as React UI
    participant A as API
    participant G as GitHub App
    participant R as Rule Engine
    participant O as OpenAI

    U->>W: Select workflow and analyze
    W->>A: Analysis request
    opt GitHub mode
      A->>G: Retrieve allowlisted workflow
      G-->>A: Read-only YAML
    end
    A->>R: Run deterministic rules
    R-->>A: Findings + validated patch
    opt Explicit AI opt-in
      A->>O: Sanitized confirmed findings
      O-->>A: Advisory explanation
    end
    A-->>W: Results, remediation, exports
```

## Security design

- GitHub App permissions are limited to read-only code and metadata.
- Installation tokens are short lived and cached only in memory.
- An application-level repository allowlist adds a second boundary.
- OpenAI receives sanitized excerpts and deterministic findings only.
- AI output is validated and treated as advisory.
- The deterministic engine re-analyzes proposed YAML before declaring a patch valid.
- Correlation IDs, rate limiting, output caching, security headers, and RFC 7807 errors support operations without logging secrets or workflow bodies.

## Deliberate exclusions

The v1.0 application does not create branches, commits, pull requests, merges, or scheduled repository scans. Those features would require a separate threat model, stronger owner authentication, new GitHub permissions, and explicit human approval.
