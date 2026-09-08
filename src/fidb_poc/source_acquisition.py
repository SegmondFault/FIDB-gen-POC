"""Inspectable resolution and acquisition of research-candidate sources.

Candidate presence in a package ecosystem is a discovery hint, not a source
pin.  This module freezes exact registry metadata, resolves candidates through
an ordered policy, writes a reviewable TOML lock, and only then permits bytes
to cross the checksum-verified source-cache boundary.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import tempfile
import tomllib
from typing import Callable
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

from .source_packs import MANAGED_SOURCE_DOWNLOADS
from .toolchain_cache import acquire_pinned, inspect_cached

ACQUISITION_SCHEMA = "fidb-source-acquisition/v1"
LOCK_SCHEMA = "fidb-source-acquisition-lock/v1"
SNAPSHOT_STATE_SCHEMA = "fidb-source-metadata-state/v1"
STATUS_SCHEMA = "fidb-source-acquisition-status/v1"
RECEIPT_SCHEMA = "fidb-source-acquisition-receipt/v1"
RESOLUTION_ALGORITHM = "ordered-source-preference-and-mirror-v2"

MANAGED_METADATA = Path("var/fidb-sources/metadata")
MANAGED_RECEIPTS = Path("var/fidb-sources/acquisition")

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[a-z0-9][a-z0-9._+-]*$")
_CONFIG_FIELDS = {
    "schema_version",
    "id",
    "label",
    "candidate_authority",
    "candidate_authority_sha256",
    "lock_path",
    "max_metadata_bytes",
    "max_archive_bytes",
    "download_workers",
    "resolver",
    "alias",
    "preference",
    "rewrite",
    "unresolved",
}
_RESOLVER_FIELDS = {"id", "kind", "priority", "url"}
_ALIAS_FIELDS = {"resolver_id", "candidate_key", "registry_key", "reason"}
_PREFERENCE_FIELDS = {"candidate_key", "resolver_id", "reason"}
_REWRITE_FIELDS = {
    "id",
    "resolver_id",
    "match_prefix",
    "replacement_prefix",
    "reason",
}
_UNRESOLVED_FIELDS = {"candidate_key", "classification", "reason"}
_LOCK_FIELDS = {
    "schema_version",
    "id",
    "label",
    "candidate_authority",
    "candidate_authority_sha256",
    "resolution_algorithm",
    "metadata_snapshot",
    "candidate",
}
_SNAPSHOT_FIELDS = {"resolver_id", "kind", "url", "sha256", "bytes"}
_LOCK_COMMON_FIELDS = {
    "rank",
    "candidate_key",
    "display_name",
    "status",
}
_LOCK_PIN_FIELDS = _LOCK_COMMON_FIELDS | {
    "resolver_id",
    "registry_key",
    "match_kind",
    "version",
    "release_page",
    "registry_url",
    "url",
    "url_rewrite_id",
    "sha256",
    "download_bytes",
    "filename",
}
_LOCK_UNRESOLVED_FIELDS = _LOCK_COMMON_FIELDS | {"reason"}
_CANDIDATE_HEADER = (
    "popularity_rank",
    "canonical_key",
    "display_name",
    "source_breadth",
    "in_debian_popcon",
    "in_homebrew",
    "in_vcpkg",
    "in_conan",
    "debian_installed_max",
    "debian_regular_use_max",
    "debian_installed_sum",
    "debian_regular_use_sum",
    "homebrew_installs_365d",
    "homebrew_requested_365d",
    "homebrew_reverse_dependencies",
    "vcpkg_reverse_dependencies",
    "conan_literal_reverse_dependencies",
    "popularity_proxy_raw",
    "popularity_proxy_share_pct",
    "cumulative_popularity_proxy_pct",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _toml(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return json.dumps(str(value), ensure_ascii=True)


def _write_atomic(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _project_path(root: Path, value: object, label: str) -> Path:
    relative = Path(str(value))
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"{label} must stay inside the project")
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise ValueError(f"{label} must stay inside the project")
    return path


def _https(value: object, label: str) -> str:
    url = str(value)
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username:
        raise ValueError(f"{label} must be an HTTPS URL without credentials")
    return url


def _fields(row: dict[str, object], expected: set[str], label: str) -> None:
    missing = sorted(expected - row.keys())
    extra = sorted(row.keys() - expected)
    if missing or extra:
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("unknown " + ", ".join(extra))
        raise ValueError(f"{label} fields are invalid: {'; '.join(details)}")


def load_acquisition(root: Path, acquisition_id: str) -> dict[str, object]:
    if _TOKEN.fullmatch(acquisition_id) is None:
        raise ValueError("source acquisition id must be a lowercase safe token")
    path = root / "sources/acquisition" / f"{acquisition_id}.toml"
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    _fields(document, _CONFIG_FIELDS, "source acquisition")
    if document["schema_version"] != ACQUISITION_SCHEMA:
        raise ValueError("unsupported source acquisition schema")
    if document["id"] != acquisition_id:
        raise ValueError("source acquisition filename and id differ")
    candidate_path = _project_path(
        root, document["candidate_authority"], "candidate authority"
    )
    digest = str(document["candidate_authority_sha256"])
    if _DIGEST.fullmatch(digest) is None or _sha256(candidate_path) != digest:
        raise ValueError("source acquisition candidate authority digest mismatch")
    lock_path = _project_path(root, document["lock_path"], "source lock")
    for field in ("max_metadata_bytes", "max_archive_bytes", "download_workers"):
        if not isinstance(document[field], int) or int(document[field]) < 1:
            raise ValueError(f"source acquisition {field} must be positive")
    resolvers = document["resolver"]
    if not isinstance(resolvers, list) or not resolvers:
        raise ValueError("source acquisition requires at least one resolver")
    resolver_ids: set[str] = set()
    priorities: set[int] = set()
    for row in resolvers:
        _fields(row, _RESOLVER_FIELDS, "source resolver")
        resolver_id = str(row["id"])
        if _TOKEN.fullmatch(resolver_id) is None or resolver_id in resolver_ids:
            raise ValueError("source resolver ids must be unique safe tokens")
        if row["kind"] not in {"homebrew-formula-json", "debian-sources-xz"}:
            raise ValueError(f"unsupported source resolver kind: {row['kind']}")
        priority = row["priority"]
        if not isinstance(priority, int) or priority < 1 or priority in priorities:
            raise ValueError("source resolver priorities must be unique and positive")
        _https(row["url"], f"source resolver {resolver_id} URL")
        resolver_ids.add(resolver_id)
        priorities.add(priority)
    aliases: set[tuple[str, str]] = set()
    for row in document["alias"]:
        _fields(row, _ALIAS_FIELDS, "source resolver alias")
        key = (str(row["resolver_id"]), str(row["candidate_key"]))
        if key[0] not in resolver_ids or key in aliases:
            raise ValueError("source resolver aliases must be unique and registered")
        if not all(str(row[field]).strip() for field in _ALIAS_FIELDS):
            raise ValueError("source resolver alias fields must be non-empty")
        aliases.add(key)
    unresolved: set[str] = set()
    for row in document["unresolved"]:
        _fields(row, _UNRESOLVED_FIELDS, "source unresolved declaration")
        key = str(row["candidate_key"])
        if not key or key in unresolved:
            raise ValueError("source unresolved candidate keys must be unique")
        if not str(row["classification"]).strip() or not str(row["reason"]).strip():
            raise ValueError("source unresolved declarations must be explained")
        unresolved.add(key)
    preferences: set[str] = set()
    for row in document["preference"]:
        _fields(row, _PREFERENCE_FIELDS, "source resolver preference")
        key = str(row["candidate_key"])
        if key in preferences or str(row["resolver_id"]) not in resolver_ids:
            raise ValueError(
                "source resolver preferences must be unique and registered"
            )
        if not key or not str(row["reason"]).strip():
            raise ValueError("source resolver preferences must be explained")
        preferences.add(key)
    rewrite_ids: set[str] = set()
    for row in document["rewrite"]:
        _fields(row, _REWRITE_FIELDS, "source URL rewrite")
        rewrite_id = str(row["id"])
        if (
            _TOKEN.fullmatch(rewrite_id) is None
            or rewrite_id in rewrite_ids
            or str(row["resolver_id"]) not in resolver_ids
        ):
            raise ValueError("source URL rewrite ids must be unique and registered")
        _https(row["match_prefix"], f"source URL rewrite {rewrite_id} match")
        _https(
            row["replacement_prefix"],
            f"source URL rewrite {rewrite_id} replacement",
        )
        if not str(row["reason"]).strip():
            raise ValueError("source URL rewrites must be explained")
        rewrite_ids.add(rewrite_id)
    return {
        **document,
        "catalog_path": str(path),
        "catalog_sha256": _sha256(path),
        "candidate_path": str(candidate_path),
        "lock_resolved_path": str(lock_path),
        "resolver": sorted(resolvers, key=lambda row: int(row["priority"])),
    }


def _csv_candidates(path: Path) -> list[dict[str, object]]:
    with path.open("r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        if tuple(reader.fieldnames or ()) != _CANDIDATE_HEADER:
            raise ValueError("source acquisition candidate authority header changed")
        rows = list(reader)
    result = []
    for expected, row in enumerate(rows, start=1):
        if int(row["popularity_rank"]) != expected:
            raise ValueError("source acquisition candidate ranks are not contiguous")
        result.append(
            {
                "rank": expected,
                "candidate_key": row["canonical_key"],
                "display_name": row["display_name"],
            }
        )
    return result


def _priority_source_families(path: Path) -> list[dict[str, object]]:
    """Project one ordered priority overlay into unique source acquisitions.

    The priority authority orders detection subjects.  Some subjects deliberately
    share one source tree (libgcc/libstdc++ and ncurses/libtinfo), so acquisition
    preserves first appearance while downloading each source family only once.
    """

    from .priority_schedule import load_priority_overlay

    root = path.resolve().parents[1]
    overlay = load_priority_overlay(root, path)
    seen: set[str] = set()
    result = []
    for subject in overlay["subjects"]:
        family = str(subject["source_family"])
        if family in seen:
            continue
        seen.add(family)
        result.append(
            {
                "rank": len(result) + 1,
                "candidate_key": family,
                "display_name": family,
            }
        )
    return result


def _candidates(path: Path) -> list[dict[str, object]]:
    if path.suffix == ".csv":
        return _csv_candidates(path)
    if path.suffix == ".toml":
        return _priority_source_families(path)
    raise ValueError("source acquisition candidate authority must be CSV or TOML")


def _metadata_state_path(root: Path, acquisition_id: str) -> Path:
    return root / MANAGED_METADATA / f"{acquisition_id}.toml"


def _render_metadata_state(
    acquisition: dict[str, object], snapshots: list[dict[str, object]]
) -> str:
    lines = [
        f"schema_version = {_toml(SNAPSHOT_STATE_SCHEMA)}",
        f'acquisition_id = {_toml(acquisition["id"])}',
        f"acquired_utc = {_toml(_now())}",
        "",
    ]
    for row in snapshots:
        lines.extend(
            [
                "[[snapshot]]",
                f'resolver_id = {_toml(row["resolver_id"])}',
                f'kind = {_toml(row["kind"])}',
                f'url = {_toml(row["url"])}',
                f'sha256 = {_toml(row["sha256"])}',
                f'bytes = {_toml(row["bytes"])}',
                f'path = {_toml(row["path"])}',
                "",
            ]
        )
    return "\n".join(lines)


def refresh_metadata(
    root: Path,
    acquisition_id: str,
    *,
    opener: Callable[..., object] = urlopen,
) -> dict[str, object]:
    """Fetch and content-address exact resolver metadata snapshots."""

    acquisition = load_acquisition(root, acquisition_id)
    snapshots = []
    maximum = int(acquisition["max_metadata_bytes"])
    for resolver in acquisition["resolver"]:
        request = Request(str(resolver["url"]), headers={"User-Agent": "fidb-poc/0.1"})
        digest = hashlib.sha256()
        total = 0
        metadata_dir = root / MANAGED_METADATA / str(resolver["id"])
        metadata_dir.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(prefix=".snapshot.", dir=metadata_dir)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as output:
                with opener(request, timeout=180) as response:
                    while block := response.read(1024 * 1024):
                        total += len(block)
                        if total > maximum:
                            raise ValueError(
                                f"resolver {resolver['id']} metadata exceeds "
                                "configured limit"
                            )
                        output.write(block)
                        digest.update(block)
                    output.flush()
                    os.fsync(output.fileno())
            sha256 = digest.hexdigest()
            destination = metadata_dir / sha256
            if destination.exists():
                if _sha256(destination) != sha256:
                    raise ValueError("existing metadata snapshot is corrupt")
                temporary.unlink()
            else:
                os.replace(temporary, destination)
            snapshots.append(
                {
                    "resolver_id": resolver["id"],
                    "kind": resolver["kind"],
                    "url": resolver["url"],
                    "sha256": sha256,
                    "bytes": total,
                    "path": str(destination.relative_to(root)),
                }
            )
        finally:
            temporary.unlink(missing_ok=True)
    state_path = _metadata_state_path(root, acquisition_id)
    _write_atomic(state_path, _render_metadata_state(acquisition, snapshots))
    return {
        "schema_version": SNAPSHOT_STATE_SCHEMA,
        "operation": "refresh",
        "acquisition_id": acquisition_id,
        "state_path": str(state_path),
        "snapshots": snapshots,
    }


def _load_metadata_state(
    root: Path, acquisition: dict[str, object]
) -> list[dict[str, object]]:
    path = _metadata_state_path(root, str(acquisition["id"]))
    state = tomllib.loads(path.read_text(encoding="utf-8"))
    if set(state) != {"schema_version", "acquisition_id", "acquired_utc", "snapshot"}:
        raise ValueError("source metadata state fields are invalid")
    if (
        state["schema_version"] != SNAPSHOT_STATE_SCHEMA
        or state["acquisition_id"] != acquisition["id"]
    ):
        raise ValueError("source metadata state authority differs")
    by_id = {str(row["id"]): row for row in acquisition["resolver"]}
    snapshots = state["snapshot"]
    if len(snapshots) != len(by_id):
        raise ValueError("source metadata state is incomplete")
    result = []
    for row in snapshots:
        if set(row) != _SNAPSHOT_FIELDS | {"path"}:
            raise ValueError("source metadata snapshot fields are invalid")
        resolver = by_id.get(str(row["resolver_id"]))
        differs = resolver and any(
            row[field] != resolver[field] for field in ("kind", "url")
        )
        if not resolver or differs:
            raise ValueError(
                "source metadata snapshot does not match resolver authority"
            )
        path = _project_path(root, row["path"], "source metadata snapshot")
        digest = str(row["sha256"])
        if _DIGEST.fullmatch(digest) is None or _sha256(path) != digest:
            raise ValueError("source metadata snapshot digest mismatch")
        if path.stat().st_size != int(row["bytes"]):
            raise ValueError("source metadata snapshot size mismatch")
        result.append({**row, "resolved_path": path})
    return result


def _homebrew_records(path: Path) -> dict[str, list[dict[str, object]]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("Homebrew metadata must be a formula list")
    result: dict[str, list[dict[str, object]]] = {}
    for formula in raw:
        if not isinstance(formula, dict) or not isinstance(formula.get("name"), str):
            raise ValueError("Homebrew formula metadata has an invalid row")
        stable = formula.get("urls", {}).get("stable", {})
        versions = formula.get("versions", {})
        checksum = stable.get("checksum")
        url = stable.get("url")
        version = versions.get("stable")
        if not isinstance(checksum, str) or _DIGEST.fullmatch(checksum) is None:
            continue
        if not isinstance(url, str) or not isinstance(version, str):
            continue
        try:
            _https(url, f"Homebrew formula {formula['name']} source")
        except ValueError:
            # The acquisition authority refuses cleartext and VCS URLs.  A
            # later resolver may still provide an immutable HTTPS archive.
            continue
        filename = Path(urlparse(url).path).name or (
            f"{formula['name']}-{version}.source"
        )
        record = {
            "resolver_id": "",
            "registry_key": formula["name"],
            "version": version,
            "release_page": (
                "https://formulae.brew.sh/formula/"
                + quote(str(formula["name"]), safe="@+._-")
            ),
            "url": url,
            "sha256": checksum,
            "download_bytes": 0,
            "filename": filename,
        }
        result.setdefault(str(formula["name"]), []).append(record)
        for alias in formula.get("aliases", []):
            if isinstance(alias, str):
                result.setdefault(alias, []).append({**record, "metadata_alias": True})
    return result


def _deb822(path: Path, maximum_uncompressed: int) -> list[dict[str, str]]:
    data = lzma.decompress(
        path.read_bytes(), memlimit=max(maximum_uncompressed * 2, 64 * 1024 * 1024)
    )
    if len(data) > maximum_uncompressed:
        raise ValueError("Debian source metadata exceeds decompression limit")
    text = data.decode("utf-8")
    rows = []
    for stanza in text.strip().split("\n\n"):
        row: dict[str, str] = {}
        key: str | None = None
        for line in stanza.splitlines():
            if line.startswith((" ", "\t")) and key is not None:
                row[key] += "\n" + line[1:]
            elif ":" in line:
                key, value = line.split(":", 1)
                row[key] = value.lstrip()
            else:
                raise ValueError("Debian source metadata has invalid control syntax")
        rows.append(row)
    return rows


def _debian_records(
    path: Path, maximum_uncompressed: int
) -> dict[str, list[dict[str, object]]]:
    grouped: dict[str, list[dict[str, str]]] = {}
    for row in _deb822(path, maximum_uncompressed):
        if "Package" in row:
            grouped.setdefault(row["Package"], []).append(row)
    result: dict[str, list[dict[str, object]]] = {}
    for package, candidates in grouped.items():
        active = [row for row in candidates if row.get("Extra-Source-Only") != "yes"]
        if not active:
            continue
        # Debian orders repeated source-package stanzas by version.  The final
        # non-Extra-Source-Only stanza is the active candidate; the metadata
        # snapshot digest makes that choice replayable and reviewable.
        row = active[-1]
        checksums = []
        for line in row.get("Checksums-Sha256", "").splitlines():
            parts = line.split()
            if len(parts) != 3 or _DIGEST.fullmatch(parts[0]) is None:
                continue
            checksums.append((parts[0], int(parts[1]), parts[2]))
        archive_suffixes = (".tar.gz", ".tar.xz", ".tar.bz2", ".tar.zst")
        archives = [
            item
            for item in checksums
            if ".orig.tar." in item[2] and item[2].endswith(archive_suffixes)
        ]
        base_archives = [item for item in archives if ".orig-" not in item[2]]
        if not base_archives:
            base_archives = [
                item
                for item in checksums
                if item[2].endswith(archive_suffixes) and ".debian.tar." not in item[2]
            ]
        if len(base_archives) != 1 or "Directory" not in row or "Version" not in row:
            continue
        digest, byte_count, filename = base_archives[0]
        directory = row["Directory"].strip("/")
        result[package] = [
            {
                "resolver_id": "",
                "registry_key": package,
                "version": row["Version"],
                "release_page": f"https://tracker.debian.org/pkg/{quote(package)}",
                "url": f"https://deb.debian.org/debian/{directory}/{quote(filename)}",
                "sha256": digest,
                "download_bytes": byte_count,
                "filename": filename,
            }
        ]
    return result


def _render_lock(document: dict[str, object]) -> str:
    lines = [
        f"schema_version = {_toml(LOCK_SCHEMA)}",
        f'id = {_toml(document["id"])}',
        f'label = {_toml(document["label"])}',
        f'candidate_authority = {_toml(document["candidate_authority"])}',
        f'candidate_authority_sha256 = {_toml(document["candidate_authority_sha256"])}',
        f"resolution_algorithm = {_toml(RESOLUTION_ALGORITHM)}",
        "",
    ]
    for row in document["metadata_snapshot"]:
        lines.append("[[metadata_snapshot]]")
        for field in ("resolver_id", "kind", "url", "sha256", "bytes"):
            lines.append(f"{field} = {_toml(row[field])}")
        lines.append("")
    for row in document["candidate"]:
        lines.append("[[candidate]]")
        fields = (
            "rank",
            "candidate_key",
            "display_name",
            "status",
            "resolver_id",
            "registry_key",
            "match_kind",
            "version",
            "release_page",
            "registry_url",
            "url",
            "url_rewrite_id",
            "sha256",
            "download_bytes",
            "filename",
            "reason",
        )
        for field in fields:
            if field in row:
                lines.append(f"{field} = {_toml(row[field])}")
        lines.append("")
    return "\n".join(lines)


def resolve_acquisition(root: Path, acquisition_id: str) -> dict[str, object]:
    """Resolve every candidate from frozen snapshots and write a TOML lock."""

    acquisition = load_acquisition(root, acquisition_id)
    snapshots = _load_metadata_state(root, acquisition)
    aliases = {
        (str(row["resolver_id"]), str(row["candidate_key"])): row
        for row in acquisition["alias"]
    }
    preferences = {
        str(row["candidate_key"]): str(row["resolver_id"])
        for row in acquisition["preference"]
    }
    rewrites = list(acquisition["rewrite"])
    declared_unresolved = {
        str(row["candidate_key"]): row for row in acquisition["unresolved"]
    }
    records: dict[str, dict[str, list[dict[str, object]]]] = {}
    for snapshot in snapshots:
        kind = str(snapshot["kind"])
        path = snapshot["resolved_path"]
        if kind == "homebrew-formula-json":
            resolved = _homebrew_records(path)  # type: ignore[arg-type]
        else:
            maximum = int(acquisition["max_metadata_bytes"]) * 8
            resolved = _debian_records(path, maximum)  # type: ignore[arg-type]
        records[str(snapshot["resolver_id"])] = resolved
    rows = []
    for candidate in _candidates(Path(str(acquisition["candidate_path"]))):
        key = str(candidate["candidate_key"])
        selected: dict[str, object] | None = None
        selection_reason = ""
        resolvers = list(acquisition["resolver"])
        preferred = preferences.get(key)
        if preferred:
            resolvers.sort(key=lambda row: str(row["id"]) != preferred)
        for resolver in resolvers:
            resolver_id = str(resolver["id"])
            alias = aliases.get((resolver_id, key))
            registry_key = str(alias["registry_key"]) if alias else key
            matches = records[resolver_id].get(registry_key, [])
            if len(matches) > 1:
                selection_reason = (
                    f"ambiguous {resolver_id} mapping for {registry_key}: "
                    f"{len(matches)} records"
                )
                break
            if len(matches) == 1:
                record = matches[0]
                if alias:
                    match_kind = "declared-alias"
                elif record.get("metadata_alias"):
                    match_kind = "registry-alias"
                else:
                    match_kind = "exact"
                registry_url = str(record["url"])
                matching_rewrites = [
                    row
                    for row in rewrites
                    if row["resolver_id"] == resolver_id
                    and registry_url.startswith(str(row["match_prefix"]))
                ]
                if len(matching_rewrites) > 1:
                    selection_reason = (
                        f"ambiguous URL rewrite for {resolver_id}:{registry_key}"
                    )
                    break
                if matching_rewrites:
                    rewrite = matching_rewrites[0]
                    source_url = (
                        str(rewrite["replacement_prefix"])
                        + registry_url[len(str(rewrite["match_prefix"])) :]
                    )
                    rewrite_id = str(rewrite["id"])
                else:
                    source_url = registry_url
                    rewrite_id = "none"
                selected = {
                    **candidate,
                    **{k: v for k, v in record.items() if k != "metadata_alias"},
                    "status": "pinned",
                    "resolver_id": resolver_id,
                    "match_kind": match_kind,
                    "registry_url": registry_url,
                    "url": source_url,
                    "url_rewrite_id": rewrite_id,
                }
                break
        if selected is None:
            declaration = declared_unresolved.get(key)
            reason = selection_reason or (
                f"{declaration['classification']}: {declaration['reason']}"
                if declaration
                else "no unique checksum-pinned source resolved"
            )
            selected = {**candidate, "status": "unresolved", "reason": reason}
        rows.append(selected)
    document = {
        "schema_version": LOCK_SCHEMA,
        "id": acquisition_id,
        "label": acquisition["label"],
        "candidate_authority": acquisition["candidate_authority"],
        "candidate_authority_sha256": acquisition["candidate_authority_sha256"],
        "resolution_algorithm": RESOLUTION_ALGORITHM,
        "metadata_snapshot": [
            {field: row[field] for field in _SNAPSHOT_FIELDS} for row in snapshots
        ],
        "candidate": rows,
    }
    path = Path(str(acquisition["lock_resolved_path"]))
    _write_atomic(path, _render_lock(document))
    pinned = sum(row["status"] == "pinned" for row in rows)
    return {
        "schema_version": LOCK_SCHEMA,
        "operation": "resolve",
        "acquisition_id": acquisition_id,
        "lock_path": str(path),
        "lock_sha256": _sha256(path),
        "summary": {
            "candidates": len(rows),
            "pinned": pinned,
            "unresolved": len(rows) - pinned,
        },
        "unresolved": [row for row in rows if row["status"] != "pinned"],
    }


def load_acquisition_lock(root: Path, acquisition_id: str) -> dict[str, object]:
    acquisition = load_acquisition(root, acquisition_id)
    path = Path(str(acquisition["lock_resolved_path"]))
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    _fields(document, _LOCK_FIELDS, "source acquisition lock")
    if (
        document["schema_version"] != LOCK_SCHEMA
        or document["id"] != acquisition_id
        or document["candidate_authority"] != acquisition["candidate_authority"]
        or document["candidate_authority_sha256"]
        != acquisition["candidate_authority_sha256"]
        or document["resolution_algorithm"] != RESOLUTION_ALGORITHM
    ):
        raise ValueError("source acquisition lock authority differs")
    snapshots = document["metadata_snapshot"]
    resolver_authority = {str(row["id"]): row for row in acquisition["resolver"]}
    if len(snapshots) != len(resolver_authority):
        raise ValueError("source acquisition lock snapshot set is incomplete")
    for row in snapshots:
        _fields(row, _SNAPSHOT_FIELDS, "source acquisition lock snapshot")
        if _DIGEST.fullmatch(str(row["sha256"])) is None:
            raise ValueError("source acquisition lock snapshot digest is invalid")
        resolver = resolver_authority.get(str(row["resolver_id"]))
        if not resolver or any(
            row[field] != resolver[field] for field in ("kind", "url")
        ):
            raise ValueError("source acquisition lock snapshot authority differs")
    rows = document["candidate"]
    if not isinstance(rows, list) or not rows:
        raise ValueError("source acquisition lock has no candidates")
    authority_candidates = _candidates(Path(str(acquisition["candidate_path"])))
    if len(rows) != len(authority_candidates):
        raise ValueError("source acquisition lock candidate set is incomplete")
    seen = set()
    for expected, (row, authority) in enumerate(
        zip(rows, authority_candidates, strict=True), start=1
    ):
        expected_fields = (
            _LOCK_PIN_FIELDS
            if row.get("status") == "pinned"
            else _LOCK_UNRESOLVED_FIELDS
        )
        _fields(row, expected_fields, "source acquisition lock candidate")
        key = str(row["candidate_key"])
        if (
            int(row["rank"]) != expected
            or key != authority["candidate_key"]
            or row["display_name"] != authority["display_name"]
            or key in seen
        ):
            raise ValueError("source acquisition lock ranks or keys are invalid")
        seen.add(key)
        if row["status"] == "pinned":
            if _DIGEST.fullmatch(str(row["sha256"])) is None:
                raise ValueError(f"source acquisition pin {key} digest is invalid")
            _https(row["url"], f"source acquisition pin {key} URL")
            _https(row["release_page"], f"source acquisition pin {key} release page")
            invalid_size = (
                not isinstance(row["download_bytes"], int)
                or int(row["download_bytes"]) < 0
            )
            if invalid_size:
                raise ValueError(f"source acquisition pin {key} size is invalid")
        elif row["status"] != "unresolved" or not str(row["reason"]).strip():
            raise ValueError(f"source acquisition candidate {key} state is invalid")
    return {
        **document,
        "lock_path": str(path),
        "lock_sha256": _sha256(path),
        "acquisition": acquisition,
    }


def acquisition_status(
    root: Path, acquisition_id: str, requested: tuple[str, ...] = ()
) -> dict[str, object]:
    lock = load_acquisition_lock(root, acquisition_id)
    rows = lock["candidate"]
    if requested:
        if len(set(requested)) != len(requested):
            raise ValueError("duplicate source acquisition candidate id")
        by_id = {str(row["candidate_key"]): row for row in rows}
        unknown = sorted(set(requested) - by_id.keys())
        if unknown:
            raise ValueError(
                "unknown source acquisition candidate: " + ", ".join(unknown)
            )
        rows = [by_id[key] for key in requested]
    downloads = root / MANAGED_SOURCE_DOWNLOADS
    projected = []
    for row in rows:
        if row["status"] == "pinned":
            inspection = inspect_cached(downloads, str(row["sha256"]))
            cache = asdict(inspection)
            cache["path"] = str(inspection.path)
        else:
            cache = {
                "state": "not-pinned",
                "path": None,
                "bytes": None,
                "observed_sha256": None,
            }
        projected.append({**row, "cache": cache})
    pinned = sum(row["status"] == "pinned" for row in projected)
    cached = sum(row["cache"]["state"] == "verified-cached" for row in projected)
    pinned_digests = {
        str(row["sha256"]) for row in projected if row["status"] == "pinned"
    }
    cached_by_digest = {
        str(row["sha256"]): int(row["cache"].get("bytes") or 0)
        for row in projected
        if row["status"] == "pinned" and row["cache"]["state"] == "verified-cached"
    }
    known_by_digest: dict[str, int] = {}
    for row in projected:
        if row["status"] != "pinned":
            continue
        digest = str(row["sha256"])
        known_by_digest[digest] = max(
            known_by_digest.get(digest, 0), int(row.get("download_bytes", 0))
        )
    return {
        "schema_version": STATUS_SCHEMA,
        "operation": "status",
        "acquisition_id": acquisition_id,
        "authority": {
            "config_path": lock["acquisition"]["catalog_path"],
            "config_sha256": lock["acquisition"]["catalog_sha256"],
            "lock_path": lock["lock_path"],
            "lock_sha256": lock["lock_sha256"],
        },
        "summary": {
            "candidates": len(projected),
            "pinned": pinned,
            "verified_cached": cached,
            "missing_or_broken": pinned - cached,
            "unresolved": len(projected) - pinned,
            "unique_pinned_payloads": len(pinned_digests),
            "duplicate_pin_references": pinned - len(pinned_digests),
            "known_download_bytes": sum(
                int(row.get("download_bytes", 0)) for row in projected
            ),
            "unique_known_download_bytes": sum(known_by_digest.values()),
            "observed_cached_bytes": sum(
                int(row["cache"].get("bytes") or 0) for row in projected
            ),
            "unique_observed_cached_bytes": sum(cached_by_digest.values()),
            "ready": cached == pinned,
        },
        "candidates": projected,
    }


def acquisition_receipt_projection(
    root: Path, acquisition_id: str
) -> dict[str, object]:
    """Project the last durable verification receipt without rehashing archives.

    The CLI ``status`` command remains the full integrity check.  This bounded
    projection is for frequently refreshed operator views: it accepts a row
    only when the receipt is bound to the current lock and the immutable cache
    object still has the recorded path and size.
    """

    lock = load_acquisition_lock(root, acquisition_id)
    receipt = root / MANAGED_RECEIPTS / f"{acquisition_id}.{lock['lock_sha256']}.toml"
    receipt_rows: dict[str, dict[str, object]] = {}
    receipt_updated_utc: str | None = None
    if receipt.exists():
        document = tomllib.loads(receipt.read_text(encoding="utf-8"))
        if (
            document.get("schema_version") != RECEIPT_SCHEMA
            or document.get("acquisition_id") != acquisition_id
            or document.get("lock_sha256") != lock["lock_sha256"]
        ):
            raise ValueError("source acquisition receipt authority differs")
        receipt_updated_utc = str(document["updated_utc"])
        receipt_rows = {
            str(row["candidate_key"]): row for row in document.get("source", [])
        }
    downloads = (root / MANAGED_SOURCE_DOWNLOADS).resolve()
    candidates = []
    for row in lock["candidate"]:
        key = str(row["candidate_key"])
        receipt_row = receipt_rows.get(key)
        receipt_cached = False
        if row["status"] == "pinned" and receipt_row:
            expected_path = downloads / str(row["sha256"])
            recorded_path = Path(str(receipt_row.get("cache_path", "")))
            try:
                receipt_cached = (
                    recorded_path.resolve() == expected_path
                    and expected_path.is_file()
                    and not expected_path.is_symlink()
                    and expected_path.stat().st_size == int(receipt_row["bytes"])
                    and receipt_row.get("sha256") == row["sha256"]
                )
            except (OSError, TypeError, ValueError):
                receipt_cached = False
        candidates.append(
            {
                "rank": row["rank"],
                "candidate_key": key,
                "status": row["status"],
                "resolver_id": row.get("resolver_id"),
                "version": row.get("version"),
                "url": row.get("url"),
                "sha256": row.get("sha256"),
                "receipt_cached": receipt_cached,
                "last_verified_utc": (
                    receipt_row.get("last_verified_utc") if receipt_row else None
                ),
                "reason": row.get("reason"),
            }
        )
    return {
        "acquisition_id": acquisition_id,
        "config_path": lock["acquisition"]["catalog_path"],
        "config_sha256": lock["acquisition"]["catalog_sha256"],
        "lock_path": lock["lock_path"],
        "lock_sha256": lock["lock_sha256"],
        "receipt_path": str(receipt),
        "receipt_updated_utc": receipt_updated_utc,
        "summary": {
            "candidates": len(candidates),
            "pinned": sum(row["status"] == "pinned" for row in candidates),
            "receipt_cached": sum(row["receipt_cached"] for row in candidates),
            "unresolved": sum(row["status"] == "unresolved" for row in candidates),
        },
        "candidates": candidates,
    }


def _render_receipt(
    status: dict[str, object],
    failures: list[dict[str, str]],
    records: list[dict[str, object]],
    created_utc: str,
) -> str:
    summary = status["summary"]
    lines = [
        f"schema_version = {_toml(RECEIPT_SCHEMA)}",
        f'acquisition_id = {_toml(status["acquisition_id"])}',
        f'lock_sha256 = {_toml(status["authority"]["lock_sha256"])}',
        f"created_utc = {_toml(created_utc)}",
        f"updated_utc = {_toml(_now())}",
        f'candidates = {_toml(summary["candidates"])}',
        f'pinned = {_toml(summary["pinned"])}',
        f'verified_cached = {_toml(summary["verified_cached"])}',
        f'missing_or_broken = {_toml(summary["missing_or_broken"])}',
        f'unresolved = {_toml(summary["unresolved"])}',
        f'unique_pinned_payloads = {_toml(summary["unique_pinned_payloads"])}',
        f'duplicate_pin_references = {_toml(summary["duplicate_pin_references"])}',
        f'observed_cached_bytes = {_toml(summary["observed_cached_bytes"])}',
        f"unique_observed_cached_bytes = "
        f'{_toml(summary["unique_observed_cached_bytes"])}',
        "",
    ]
    for row in sorted(records, key=lambda item: int(item["rank"])):
        lines.append("[[source]]")
        for field in (
            "rank",
            "candidate_key",
            "resolver_id",
            "registry_key",
            "version",
            "registry_url",
            "url",
            "url_rewrite_id",
            "sha256",
            "bytes",
            "cache_path",
            "outcome",
            "first_observed_utc",
            "downloaded_utc",
            "last_verified_utc",
        ):
            lines.append(f"{field} = {_toml(row[field])}")
        lines.append("")
    for row in failures:
        lines.extend(
            [
                "[[failure]]",
                f'candidate_key = {_toml(row["candidate_key"])}',
                f'error_type = {_toml(row["error_type"])}',
                f'error = {_toml(row["error"])}',
                f'observed_utc = {_toml(row["observed_utc"])}',
                "",
            ]
        )
    return "\n".join(lines)


def _existing_receipt(
    path: Path, lock_sha256: str
) -> tuple[str, dict[str, dict[str, object]], list[dict[str, str]]]:
    if not path.exists():
        return _now(), {}, []
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if (
        document.get("schema_version") != RECEIPT_SCHEMA
        or document.get("lock_sha256") != lock_sha256
    ):
        raise ValueError("source acquisition receipt authority differs")
    records = {
        str(row["candidate_key"]): dict(row) for row in document.get("source", [])
    }
    failures = [dict(row) for row in document.get("failure", [])]
    return str(document["created_utc"]), records, failures


def pull_acquisition(
    root: Path,
    acquisition_id: str,
    requested: tuple[str, ...] = (),
    *,
    workers: int | None = None,
    progress: Callable[[str], None] | None = None,
) -> dict[str, object]:
    """Acquire every selected pin concurrently; preserve failures and continue."""

    before = acquisition_status(root, acquisition_id, requested)
    config = load_acquisition(root, acquisition_id)
    worker_count = workers or int(config["download_workers"])
    if worker_count < 1 or worker_count > 32:
        raise ValueError("source acquisition workers must be between 1 and 32")
    pending = [
        row
        for row in before["candidates"]
        if row["status"] == "pinned" and row["cache"]["state"] != "verified-cached"
    ]
    failures: list[dict[str, str]] = []
    acquisitions = []
    receipt = (
        root
        / MANAGED_RECEIPTS
        / f"{acquisition_id}.{before['authority']['lock_sha256']}.toml"
    )
    created_utc, receipt_records, historical_failures = _existing_receipt(
        receipt, str(before["authority"]["lock_sha256"])
    )
    started_utc = _now()
    for row in before["candidates"]:
        if row["cache"]["state"] != "verified-cached":
            continue
        key = str(row["candidate_key"])
        existing = receipt_records.get(key)
        receipt_records[key] = {
            "rank": row["rank"],
            "candidate_key": key,
            "resolver_id": row["resolver_id"],
            "registry_key": row["registry_key"],
            "version": row["version"],
            "registry_url": row["registry_url"],
            "url": row["url"],
            "url_rewrite_id": row["url_rewrite_id"],
            "sha256": row["sha256"],
            "bytes": int(row["cache"]["bytes"]),
            "cache_path": row["cache"]["path"],
            "outcome": (
                existing.get("outcome") if existing else "pre-existing-verified-cache"
            ),
            "first_observed_utc": (
                existing.get("first_observed_utc") if existing else started_utc
            ),
            "downloaded_utc": existing.get("downloaded_utc", "") if existing else "",
            "last_verified_utc": started_utc,
        }

    def write_receipt(status: dict[str, object]) -> None:
        _write_atomic(
            receipt,
            _render_receipt(
                status,
                [*historical_failures, *failures],
                list(receipt_records.values()),
                created_utc,
            ),
        )

    write_receipt(before)

    def acquire(row: dict[str, object]) -> tuple[dict[str, object], object]:
        result = acquire_pinned(
            str(row["url"]),
            str(row["sha256"]),
            root / MANAGED_SOURCE_DOWNLOADS,
            timeout_seconds=180,
            attempts=4,
            max_bytes=int(config["max_archive_bytes"]),
        )
        expected = int(row["download_bytes"])
        if expected and result.bytes != expected:
            raise ValueError(
                f"pinned size mismatch: expected {expected}, observed {result.bytes}"
            )
        return row, result

    if progress:
        progress(
            f"source acquisition {acquisition_id}: {len(pending)} missing pins, "
            f"{worker_count} download workers"
        )
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {executor.submit(acquire, row): row for row in pending}
        complete = 0
        for future in as_completed(futures):
            row = futures[future]
            complete += 1
            try:
                _, result = future.result()
                values = asdict(result)
                values["path"] = str(result.path)
                values["quarantined"] = (
                    str(result.quarantined) if result.quarantined else None
                )
                acquisitions.append({"candidate_key": row["candidate_key"], **values})
                outcome = "cached" if result.cache_hit else "downloaded"
                observed_utc = _now()
                existing = receipt_records.get(str(row["candidate_key"]))
                receipt_records[str(row["candidate_key"])] = {
                    "rank": row["rank"],
                    "candidate_key": row["candidate_key"],
                    "resolver_id": row["resolver_id"],
                    "registry_key": row["registry_key"],
                    "version": row["version"],
                    "registry_url": row["registry_url"],
                    "url": row["url"],
                    "url_rewrite_id": row["url_rewrite_id"],
                    "sha256": row["sha256"],
                    "bytes": result.bytes,
                    "cache_path": str(result.path),
                    "outcome": outcome,
                    "first_observed_utc": (
                        existing.get("first_observed_utc") if existing else observed_utc
                    ),
                    "downloaded_utc": (
                        (existing.get("downloaded_utc", "") if existing else "")
                        or (observed_utc if not result.cache_hit else "")
                    ),
                    "last_verified_utc": observed_utc,
                }
            except Exception as error:  # keep the rest of the independent set running
                failures.append(
                    {
                        "candidate_key": str(row["candidate_key"]),
                        "error_type": type(error).__name__,
                        "error": str(error),
                        "observed_utc": _now(),
                    }
                )
                outcome = f"FAILED {type(error).__name__}"
            interim = {
                **before,
                "summary": {
                    **before["summary"],
                    "verified_cached": len(receipt_records),
                    "missing_or_broken": int(before["summary"]["pinned"])
                    - len(receipt_records),
                    "observed_cached_bytes": sum(
                        int(item["bytes"]) for item in receipt_records.values()
                    ),
                    "unique_observed_cached_bytes": sum(
                        {
                            str(item["sha256"]): int(item["bytes"])
                            for item in receipt_records.values()
                        }.values()
                    ),
                },
            }
            write_receipt(interim)
            if progress:
                progress(
                    f"[{complete}/{len(pending)}] {row['candidate_key']}: {outcome}"
                )
    after = acquisition_status(root, acquisition_id, requested)
    after["operation"] = "pull"
    after["download_workers"] = worker_count
    after["acquisitions"] = acquisitions
    after["failures"] = failures
    write_receipt(after)
    after["receipt_path"] = str(receipt)
    return after
