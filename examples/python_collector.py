"""Send JSONL security events to SentinelScope without third-party packages."""

import argparse
import json
import os
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def load_events(path: Path) -> list[dict]:
    events = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON on line {line_number}") from exc
    if not events:
        raise ValueError("The input file contains no events")
    return events


def send_batch(endpoint: str, api_key: str, events: list[dict]) -> dict:
    request = Request(
        endpoint,
        data=json.dumps({"events": events}).encode(),
        headers={"Content-Type": "application/json", "X-Ingestion-Key": api_key},
        method="POST",
    )
    try:
        # The collector intentionally sends to an operator-configured HTTP(S) ingestion endpoint.
        with urlopen(request, timeout=15) as response:  # nosec B310
            return json.loads(response.read())
    except HTTPError as exc:
        raise RuntimeError(f"Ingestion failed ({exc.code}): {exc.read().decode()}") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description="Send JSONL events to SentinelScope")
    parser.add_argument("jsonl", type=Path)
    parser.add_argument(
        "--endpoint",
        default="http://localhost:8000/api/v1/ingest/events",
    )
    args = parser.parse_args()
    api_key = os.environ.get("SENTINELSCOPE_INGESTION_KEY")
    if not api_key:
        raise SystemExit("Set SENTINELSCOPE_INGESTION_KEY before running the collector")
    result = send_batch(args.endpoint, api_key, load_events(args.jsonl))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
