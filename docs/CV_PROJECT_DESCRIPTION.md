# CV and Interview Description

## Turkish CV version

**SentinelScope — Açıklanabilir Akıllı Güvenlik İzleme Platformu**

Python, FastAPI, React, PostgreSQL, SQLAlchemy, scikit-learn, Docker, GitHub Actions

Repository: https://github.com/bbmuti/SecureOps

- Windows Security Event Log, Linux OpenSSH ve JSON/JSONL kaynaklarından güvenlik olaylarını alan tam kapsamlı bir izleme platformu geliştirdim.
- Kural tabanlı tespitleri Isolation Forest davranış analiziyle birleştirerek açıklanabilir 0–100 risk puanı, MITRE ATT&CK eşleştirmesi ve kanıta dayalı alarm üretimi sağladım.
- HttpOnly cookie, CSRF koruması, atomik refresh-token ailesi rotasyonu ve replay iptali; rate limiting, idempotent veri alımı, audit log, Alembic ve PostgreSQL desteği uyguladım.
- Gerçek BETH process telemetrisinde üç seed’li 1.000 ağaçlı ensemble ile 100.000 kayıt üzerinde %94,28 F1 ölçen; güven aralığı, random baseline ve veri hash’leri içeren tekrarlanabilir araştırma benchmarkı geliştirdim.
- Backend/frontend testleri, branch coverage kapısı, PostgreSQL smoke testi, Python/npm güvenlik denetimi, Windows collector kontrolü ve container build içeren GitHub Actions süreci kurdum.

## English CV version

**SentinelScope — Explainable Intelligent Security Monitoring Platform**

Python, FastAPI, React, PostgreSQL, SQLAlchemy, scikit-learn, Docker, GitHub Actions

Repository: https://github.com/bbmuti/SecureOps

- Built a full-stack monitoring platform that ingests security telemetry from Windows Security Event Log, Linux OpenSSH, and JSON/JSONL sources.
- Combined deterministic detections with Isolation Forest behavior scoring to generate explainable 0–100 risk scores, evidence, and MITRE ATT&CK context.
- Implemented HttpOnly cookie sessions with CSRF protection, atomic refresh-token family rotation and replay revocation, rate limiting, idempotent ingestion, audit logging, Alembic, and PostgreSQL.
- Established CI gates for backend/frontend tests, branch coverage, PostgreSQL smoke testing, Python/npm audits, Windows collector validation, and container builds.
- Built a reproducible external BETH process-telemetry benchmark using a three-seed 1,000-tree ensemble, bootstrap intervals, a random baseline, dataset hashes, and a 0.9428 F1 score on a 100,000-record test sample.

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
