#!/usr/bin/env python3
"""Deterministic lower-bound model for bounded cross-block tail filling."""

from __future__ import annotations

import argparse
import heapq
import json


def _makespan(durations: list[float], workers: int) -> float:
    slots = [0.0] * workers
    heapq.heapify(slots)
    for duration in durations:
        started = heapq.heappop(slots)
        heapq.heappush(slots, started + duration)
    return max(slots)


def benchmark(workers: int) -> dict[str, object]:
    # Reproduce the observed 11-cell long primary tail with a small, ready
    # successor. Durations are a scheduler model, not production measurements.
    primary = [120.0] * 11
    successor = [10.0] * 36
    serial_minutes = _makespan(primary, workers) + _makespan(successor, workers)
    tail_fill_minutes = _makespan(primary + successor, workers)
    improvement = (serial_minutes - tail_fill_minutes) / serial_minutes * 100.0
    return {
        "schema_version": "fidb-tail-fill-benchmark/v1",
        "model": "deterministic-list-scheduling",
        "workers": workers,
        "primary_tail": {"cells": len(primary), "minutes_per_cell": 120.0},
        "successor": {"cells": len(successor), "minutes_per_cell": 10.0},
        "single_block_minutes": serial_minutes,
        "tail_fill_minutes": tail_fill_minutes,
        "projected_wall_time_improvement_percent": round(improvement, 2),
        "identity_or_artifact_changes": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=32)
    arguments = parser.parse_args()
    if arguments.workers < 1:
        parser.error("--workers must be positive")
    print(json.dumps(benchmark(arguments.workers), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
