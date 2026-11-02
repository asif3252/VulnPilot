# Security policy

This is a local single-user portfolio prototype. Do not use it as a public-facing service or as the sole basis for patch, containment or risk-acceptance decisions.

## Boundaries

- Server: Python standard-library HTTP server, bound only to 127.0.0.1.
- Writes: exact loopback Host and Origin plus per-process anti-CSRF token.
- Browser: same-origin scripts/styles, no third-party UI assets, HTML escaping.
- Storage: local SQLite with parameterized SQL, no encryption at rest.
- Feed fetches: fixed HTTPS endpoints, response size caps, timeouts, no redirect following.
- Imports: strict normalized contracts and limits. No uploaded code or model execution.
- Exports: CSV formula neutralization; JSON still contains original internal asset/notes data.

These controls are not a penetration-test certification. Local malware, another user with filesystem access and resource exhaustion remain outside the prototype's protection. The activity log is editable by anyone with database access and has no authenticated identity trail.

## Report problems

Report a reproducible non-sensitive defect through the project's issue tracker when published. Use the maintainer's professional contact for sensitive issues. Do not publish private captures, asset lists, credentials or exploit details in public issues. No security response SLA is promised.
