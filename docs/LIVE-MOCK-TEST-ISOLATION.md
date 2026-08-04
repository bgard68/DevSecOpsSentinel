# Live and Mock OpenAI Test Isolation

## Purpose

Local and deployed application runs may use `OpenAI:Mode=Live` through .NET User Secrets or environment variables. Automated integration tests must never inherit those developer settings or make billable OpenAI requests.

## Implementation

- The integration-test host runs under the `Testing` environment.
- ASP.NET Core User Secrets are not loaded for the `Testing` environment.
- The test factory explicitly sets `OpenAI:Mode=Mock`, clears `OpenAI:ApiKey`, fixes the test model, and disables live GitHub access.
- OpenAPI and Scalar remain available in the `Testing` environment so API-documentation tests remain deterministic.
- Status tests deserialize the response and verify the expected Mock configuration without searching for incidental strings.

## Result

- Developers can keep `OpenAI:Mode=Live` locally.
- Tests always use Mock mode.
- Tests consume no OpenAI credits.
- Live credentials cannot change test outcomes.
