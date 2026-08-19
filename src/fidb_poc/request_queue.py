from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path

FIELDNAMES = (
    "library_request",
    "priority",
    "status",
    "resolution_lane",
    "requested_routes",
    "first_requested_utc",
    "last_requested_utc",
    "request_count",
    "candidate_version",
    "candidate_source_url",
    "candidate_sha256",
    "notes",
)


def _timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _normalise_request(value: str) -> str:
    return " ".join(value.strip().lower().split())


def _merge_routes(existing: str, requested: tuple[str, ...]) -> str:
    routes = {route for route in existing.split(";") if route}
    routes.update(requested)
    return ";".join(sorted(routes))


def _read_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if tuple(reader.fieldnames or ()) != FIELDNAMES:
            raise ValueError(f"unsupported recipe-request CSV columns in {path}")
        return list(reader)


def record_missing_requests(
    path: Path,
    requests: tuple[str, ...],
    *,
    priority: int,
    routes: tuple[str, ...],
    now: str | None = None,
) -> Path:
    if priority not in {0, 1, 2}:
        raise ValueError("request priority must be 0, 1 or 2")
    timestamp = now or _timestamp()
    rows = _read_rows(path)
    by_request = {_normalise_request(row["library_request"]): row for row in rows}

    for requested_name in requests:
        key = _normalise_request(requested_name)
        if not key:
            raise ValueError("library request cannot be empty")
        existing = by_request.get(key)
        if existing is None:
            existing = {
                "library_request": requested_name.strip(),
                "priority": str(priority),
                "status": "pending",
                "resolution_lane": "source_discovery",
                "requested_routes": ";".join(sorted(set(routes))),
                "first_requested_utc": timestamp,
                "last_requested_utc": timestamp,
                "request_count": "1",
                "candidate_version": "",
                "candidate_source_url": "",
                "candidate_sha256": "",
                "notes": "",
            }
            rows.append(existing)
            by_request[key] = existing
            continue
        existing["priority"] = str(min(int(existing["priority"]), priority))
        existing["requested_routes"] = _merge_routes(
            existing["requested_routes"], routes
        )
        existing["last_requested_utc"] = timestamp
        existing["request_count"] = str(int(existing["request_count"]) + 1)

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)
    return path
