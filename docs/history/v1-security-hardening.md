# v1 security hardening follow-up

This change set closes the post-v1 review findings without changing the
application's read-only GitHub posture.

## Deterministic core

Action tag-to-SHA resolution is disabled by default. Ordinary scenario and
pasted-workflow analysis does not make outbound GitHub requests. When explicitly
enabled, resolution failures leave the original reference unchanged and appear
as patch warnings.

## Test isolation

API integration tests replace the action resolver with a deterministic stub.
CI no longer depends on GitHub network availability or shared-runner rate
limits.

## Authentication clients

The React client supports a session-only access key entered by the operator.
No key is built into the bundle or persisted to local storage. PowerShell smoke
tests accept `-ApiKey` or `DEVSECOPS_SENTINEL_API_KEY`.

## Configuration and rate limiting

API security uses `IOptionsMonitor`. Authentication is permitted to be disabled
only in Development and Testing. Workflow rate limits are partitioned by a hash
of the authenticated API key, falling back to the remote IP address.

## Additional hardening

- RFC 7807 unauthorized responses
- Content Security Policy headers
- Explicit request-body limits
- Expanded secret sanitizer tests
- Logged GitHub/OpenAI provider failures
- Valid unified-diff hunk headers
- Aligned `gpt-5-mini` defaults
- Restricted local `AllowedHosts`
