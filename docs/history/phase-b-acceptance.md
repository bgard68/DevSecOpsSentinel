# Phase B acceptance

- [ ] `.slnx` opens and builds, or `.sln` fallback is used
- [ ] `/` returns 200
- [ ] `/api/health` returns 200
- [ ] rules and scenarios endpoints return 200
- [ ] four deterministic rules execute
- [ ] malformed workflow content returns 422
- [ ] empty requests return 400
- [ ] oversized content returns 413
- [ ] unsupported media type returns 415
- [ ] proposed content is reparsed successfully
- [ ] backend unit and integration tests pass
- [ ] frontend tests and build pass
- [ ] PowerShell smoke matrix passes
- [ ] repository protection scan passes
- [ ] no secrets, `.claude`, logs, or Azure import/export artifacts are tracked

- [ ] `/openapi/v1.json` returns the generated OpenAPI document in Development
- [ ] `/scalar` displays the interactive Scalar API reference in Development
- [ ] Swagger UI and Swashbuckle are not installed
