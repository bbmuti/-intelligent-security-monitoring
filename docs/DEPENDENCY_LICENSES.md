# Direct Dependency License Review

This inventory records the direct runtime and development dependency families used by SentinelScope. It is a release-review aid, not legal advice; the exact license files distributed by each installed package remain authoritative.

| Component family | Declared license | Use in this repository |
|---|---|---|
| FastAPI, SQLAlchemy, PyJWT, Alembic, pydantic-settings | MIT | Python API, data and migration layers |
| Starlette, Uvicorn, scikit-learn, NumPy | BSD-style | ASGI runtime and machine learning |
| HTTPX2 | BSD-3-Clause | API test client |
| Psycopg 3 | LGPL-3.0 | Dynamically imported PostgreSQL driver; not modified or vendored |
| React, React DOM, Vite, Testing Library, Vitest, jsdom | MIT | Frontend runtime, build and tests |
| Lucide | ISC | UI icons |
| Playwright | Apache-2.0 | Browser end-to-end tests |
| pytest, pytest-cov, Ruff | MIT | Python tests, coverage and linting |
| Bandit, pip-audit | Apache-2.0 | Static security and dependency vulnerability checks |
| PostgreSQL | PostgreSQL License | Docker service image |
| Nginx unprivileged image | BSD-2-Clause | Reverse proxy/static web image |
| BETH dataset | CC0-1.0 | External benchmark input; raw data is not redistributed |

These licenses permit this repository's MIT-licensed source distribution when their notices and conditions are respected. The project imports dependencies normally and does not copy their source into SentinelScope. Binary images and Python wheels may contain additional compatible notices; review the exact release artifacts again before commercial redistribution.

Release verification should include:

1. Recreate Python and npm environments from the pinned manifests.
2. Generate a complete transitive SBOM/license report for the release images.
3. Review any unknown, GPL/AGPL, custom, or license-changed package before publishing.
4. Preserve upstream copyright and license files in redistributed binary bundles.
