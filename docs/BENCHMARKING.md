# Reproducible External Benchmarking

SentinelScope keeps two evaluations deliberately separate:

1. `scripts/evaluate_model.py` is a deterministic synthetic regression check for the complete hybrid rule-and-anomaly path.
2. `scripts/benchmark_beth.py` evaluates the Isolation Forest algorithm family on labeled, real host telemetry from BETH.

Neither result should be presented as the other. In particular, the BETH benchmark is not an end-to-end measurement of the authentication/API event schema.

## Why BETH

[BETH](https://www.kaggle.com/datasets/katehighnam/beth-dataset) contains more than eight million real process events collected from 23 cloud honeypots and includes benign and malicious labels. The dataset is released under CC0. The accompanying research paper is [BETH Dataset: Real Cybersecurity Data for Unsupervised Anomaly Detection Research](https://www.gatsby.ucl.ac.uk/~balaji/udl2021/accepted-papers/UDL2021-paper-033.pdf).

The reproducible run in this repository uses the public author-owned Kaggle release, version 3:

```text
https://www.kaggle.com/datasets/katehighnam/beth-dataset
```

The Kaggle archive is approximately 42 MB compressed and 928 MB after extraction. It is intentionally not committed to this repository.

## Run the benchmark

Download and extract the official archive. Then run from `backend/`:

```bash
python -m scripts.benchmark_beth \
  --train /path/to/labelled_training_data.csv \
  --validation /path/to/labelled_validation_data.csv \
  --test /path/to/labelled_testing_data.csv \
  --max-train 100000 \
  --max-validation 100000 \
  --max-test 100000 \
  --output artifacts/beth-benchmark.json
```

The script uses deterministic reservoir sampling, fits only benign training records, selects the decision threshold from the 95th percentile of the separate benign-only validation split (a 5% validation alert budget), and evaluates that frozen threshold once on the labelled test split. It reports:

- precision, recall, and F1;
- ROC-AUC and average precision;
- false-positive rate;
- confusion matrix;
- sampled class counts;
- SHA-256 hashes of both input files.

File hashes for all three splits, fixed seeds, feature names, sampling limits, and threshold methodology make a result reproducible. Do not commit the downloaded dataset. A generated report may be committed only when it was produced by this script without manual metric editing.

## Versioned result

The committed [BETH report](../backend/artifacts/beth-benchmark.json) was generated on 2026-08-20 from version 3 with 100,000 sampled records in each stage:

| Metric | Test result |
|---|---:|
| Precision | 0.9716 |
| Recall | 0.9145 |
| F1 | 0.9422 |
| ROC-AUC | 0.8449 |
| Average precision | 0.9382 |
| False-positive rate | 0.1397 |

The strong precision and recall do not cancel out the 13.97% benign test false-positive rate. That gap is recorded as a model-improvement target rather than hidden.

## Interpretation

Accuracy alone is misleading for rare security events. Prioritize recall, precision, average precision, and false-positive rate. A useful detector must find attacks without producing an alert volume that analysts cannot triage.

The BETH benchmark validates the anomaly-detection algorithm on real process telemetry. A separate LANL authentication benchmark is a future extension because the official comprehensive LANL authentication file is 7.2 GB compressed.
