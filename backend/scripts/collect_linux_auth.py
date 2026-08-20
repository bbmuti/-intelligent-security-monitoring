"""Send OpenSSH login records from a Linux auth log to SentinelScope."""

import argparse
import json
import os
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from app.integrations.linux_auth import parse_linux_auth_line


def send(endpoint: str, api_key: str, events: list[dict]) -> dict:
    request = Request(
        endpoint,
        data=json.dumps({"events": events}).encode(),
        headers={"Content-Type": "application/json", "X-Ingestion-Key": api_key},
        method="POST",
    )
    try:
        with urlopen(request, timeout=15) as response:  # nosec B310
            return json.loads(response.read())
    except HTTPError as exc:
        raise RuntimeError(f"Ingestion failed ({exc.code}): {exc.read().decode()}") from exc


def collect_once(path: Path) -> list[dict]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return [event for line in lines if (event := parse_linux_auth_line(line))]


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect OpenSSH events from /var/log/auth.log")
    parser.add_argument("--file", type=Path, default=Path("/var/log/auth.log"))
    parser.add_argument("--endpoint", default="http://localhost:8000/api/v1/ingest/events")
    parser.add_argument("--follow", action="store_true", help="Tail new records continuously")
    parser.add_argument("--dry-run", action="store_true", help="Print normalized events without sending")
    args = parser.parse_args()

    api_key = os.environ.get("SENTINELSCOPE_INGESTION_KEY", "")
    if not args.dry_run and not api_key:
        raise SystemExit("Set SENTINELSCOPE_INGESTION_KEY before running the collector")

    if not args.follow:
        events = collect_once(args.file)
        if args.dry_run:
            print(json.dumps(events, indent=2))
            return
        for offset in range(0, len(events), 100):
            print(json.dumps(send(args.endpoint, api_key, events[offset : offset + 100]), indent=2))
        return

    with args.file.open(encoding="utf-8", errors="replace") as handle:
        handle.seek(0, 2)
        while True:
            line = handle.readline()
            if not line:
                time.sleep(0.5)
                continue
            event = parse_linux_auth_line(line)
            if event:
                if args.dry_run:
                    print(json.dumps(event))
                else:
                    print(json.dumps(send(args.endpoint, api_key, [event])))


if __name__ == "__main__":
    main()
