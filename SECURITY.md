# Security policy

## Repository rules

Never commit credentials, API keys, passwords, personal access tokens, GitHub
App private keys, certificates, Azure publish profiles, Azure imports or
exports, `.claude`, conversation content, production configuration, or logs.

Phase B is intentionally local and stateless. It does not connect to GitHub,
Azure, OpenAI, or a database. Visitor scenarios are bundled sample files.

## Reporting

Do not open a public issue containing a live secret or exploit payload. Revoke
any exposed credential first, remove it from Git history, and report the issue
privately to the repository owner.
