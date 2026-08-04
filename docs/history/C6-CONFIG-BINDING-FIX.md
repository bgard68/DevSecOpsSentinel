# C6 test configuration binding fix

The API security options were read and frozen during `Program.cs` execution. `WebApplicationFactory.ConfigureAppConfiguration` applies integration-test overrides later in the host-building process, so the middleware retained the default `Disabled` mode.

This fix:

- removes the frozen `ApiSecurityOptions` singleton;
- reads current configuration inside the authentication middleware;
- validates the final configuration after `builder.Build()`;
- evaluates allowed CORS origins against the current configuration.

No real API keys are added or changed.
