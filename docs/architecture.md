# Architecture

```text
React dashboard
    |
    | HTTP JSON
    v
Minimal API endpoints
    |
    v
IWorkflowAnalysisService
    |-- IWorkflowParser
    |-- IEnumerable<IWorkflowSecurityRule>
    `-- IWorkflowPatchGenerator
```

The Domain project contains immutable result models. Application owns use-case
contracts and orchestration. Infrastructure implements workflow parsing,
scenarios, rules, and patch generation. API owns HTTP concerns. No mediator or
persistence abstraction is introduced because Phase B does not need either.


## API documentation

The API uses ASP.NET Core's built-in OpenAPI document generation. Scalar renders
that document as an interactive Development-only API reference. Swashbuckle and
Swagger UI are intentionally not used.
