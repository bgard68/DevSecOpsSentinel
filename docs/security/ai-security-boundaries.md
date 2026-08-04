# AI security boundaries

- AI is opt-in per request.
- The React application never receives the API key.
- Potential credentials and private-key blocks are redacted before provider calls.
- Only one workflow excerpt and deterministic findings are sent.
- Structured output must contain exactly the known rule IDs.
- Invalid output, timeouts, missing keys, and provider errors fall back safely.
- Prompts and workflow contents are not logged by default.
