# Security Policy

## Project scope

SentinelScope is an educational defensive-security MVP and is not offered as a hosted production service. The simulator creates application records only; it does not perform network discovery, exploitation, credential attacks, or traffic interception.

## Reporting a vulnerability

Please do not disclose a suspected vulnerability in a public issue. Use the repository's [private vulnerability reporting flow](https://github.com/bbmuti/-intelligent-security-monitoring/security/advisories/new) and include:

- the affected component and version or commit;
- clear reproduction steps;
- expected and observed behavior;
- the potential security impact;
- a suggested mitigation, if available.

Do not include real credentials, personal data, access tokens, or production logs. Reports will be acknowledged and evaluated before a public fix or advisory is prepared.

## Deployment boundary

The included Compose stack keeps PostgreSQL and FastAPI on an internal network and publishes only a non-root, read-only Nginx container. Browser refresh sessions use HttpOnly/SameSite cookies, double-submit CSRF protection, atomic token-family rotation, and replay-family revocation. These controls reduce risk but do not make the repository a managed internet service.

Before any internet-facing deployment:

1. Set `ENVIRONMENT=production`.
2. Replace every example credential and key with independently generated secrets.
3. Terminate TLS at a trusted reverse proxy or managed ingress.
4. Restrict CORS origins and database/network access.
5. Use managed secret storage, backups, retention controls, monitoring, and a distributed rate limiter.
6. Complete an independent threat model, dependency review, and penetration test.

The repository includes a scoped [threat model](docs/THREAT_MODEL.md) and intentionally documents residual limitations in the README rather than claiming production readiness.
