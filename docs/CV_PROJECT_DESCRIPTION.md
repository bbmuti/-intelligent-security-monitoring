# CV and Interview Description

## Turkish CV version

**SentinelScope — Açıklanabilir Akıllı Güvenlik İzleme Platformu**

Python, FastAPI, React, PostgreSQL, SQLAlchemy, scikit-learn, Docker, GitHub Actions

- Windows Security Event Log, Linux OpenSSH ve JSON/JSONL kaynaklarından güvenlik olaylarını alan tam kapsamlı bir izleme platformu geliştirdim.
- Kural tabanlı tespitleri Isolation Forest davranış analiziyle birleştirerek açıklanabilir 0–100 risk puanı, MITRE ATT&CK eşleştirmesi ve kanıta dayalı alarm üretimi sağladım.
- Döndürülebilir refresh token, rate limiting, servis kimlik doğrulaması, audit log, Alembic migrasyonları ve PostgreSQL desteği uyguladım.
- Gerçek BETH telemetrisinde 100.000 kayıtlı test üzerinde %94,22 F1 elde eden tekrarlanabilir Isolation Forest benchmarkı; 39 backend testi, %80 coverage kalite kapısı, Ruff, Bandit, Dependabot ve otomatik frontend build içeren CI/CD süreci kurdum.

## English CV version

**SentinelScope — Explainable Intelligent Security Monitoring Platform**

Python, FastAPI, React, PostgreSQL, SQLAlchemy, scikit-learn, Docker, GitHub Actions

- Built a full-stack monitoring platform that ingests security telemetry from Windows Security Event Log, Linux OpenSSH, and JSON/JSONL sources.
- Combined deterministic detections with Isolation Forest behavior scoring to generate explainable 0–100 risk scores, evidence, and MITRE ATT&CK context.
- Implemented rotating refresh sessions, rate limiting, service authentication, audit logging, Alembic migrations, and PostgreSQL support.
- Established CI quality gates covering 39 backend tests, 93% branch coverage, Ruff, Bandit, database migrations, and the production frontend build.
- Added a reproducible external BETH benchmark with deterministic sampling, dataset hashes, and a 0.9422 F1 score on a 100,000-record test sample.

## Interview explanation

Start with the problem: security analysts need prioritized evidence, not an unexplained malicious/benign label. Then explain the event pipeline, the hybrid detection decision, and one alert lifecycle. Be ready to distinguish:

- deterministic smoke testing from external dataset benchmarking;
- a model anomaly from proof of an attack;
- an educational production-shaped MVP from a production SIEM.

## Likely technical questions

1. Why combine rules and machine learning instead of using one approach?
2. Why Isolation Forest, and how is its threshold selected?
3. How do you prevent future events from leaking into a historical decision?
4. Why are refresh tokens stored server-side and rotated?
5. How would you replace the in-memory rate limiter for multiple API replicas?
6. How do you control false positives and class imbalance?
7. What would be required before an internet-facing production deployment?
