# AI cost controls

- Default mode is `Mock`, which consumes no OpenAI credits.
- Live requests occur only when a user selects **Include AI explanation**.
- No background jobs or polling call OpenAI.
- Context length and request timeout are bounded in `OpenAI` configuration.
- Provider errors do not trigger an unbounded retry loop.
- Keep prepaid auto-reload disabled for the strongest account-level protection.
