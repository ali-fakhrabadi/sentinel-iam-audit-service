#!/usr/bin/env python3
"""Turn k6 ``--summary-export`` JSON files into a Markdown results table.

python3 loadtest/summarize_k6.py loadtest/results/raw/*.json > loadtest/results/summary.md
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def _ms(value: float | None) -> str:
    return "-" if value is None else f"{value:,.1f}"


def rows(path: Path) -> list[list[str]]:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    metrics: dict[str, Any] = data["metrics"]
    failed = metrics.get("http_req_failed", {}).get("value", 0.0)
    events_rate = metrics.get("events_accepted", {}).get("rate")
    result = []
    for name, metric in sorted(metrics.items()):
        if not name.startswith("http_req_duration{name:"):
            continue
        tag = name.split(":", 1)[1].rstrip("}")
        counter = metrics.get(f"http_reqs{{name:{tag}}}", {})
        requests, rate = counter.get("count"), counter.get("rate")
        throughput = f"{rate:,.1f} req/s" if rate else "-"
        if events_rate and tag == "bulk_ingest":
            throughput += f" ({events_rate:,.0f} events/s)"
        result.append(
            [
                path.stem,
                tag,
                f"{requests:,}" if requests else "-",
                throughput,
                _ms(metric.get("med")),
                _ms(metric.get("p(95)")),
                _ms(metric.get("p(99)")),
                f"{failed * 100:.2f} %",
            ]
        )
    return result


def main(paths: list[str]) -> int:
    header = ["Run", "Operation", "Requests", "Throughput", "p50 ms", "p95 ms", "p99 ms", "Errors"]
    print("| " + " | ".join(header) + " |")
    print("|" + "---|" * len(header))
    for raw in paths:
        for row in rows(Path(raw)):
            print("| " + " | ".join(row) + " |")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
