"""Reviewed, source-only library packs and managed acquisition.

Source packs pin release archives without pretending that a build recipe is
already qualified.  Acquisition reuses the locked, content-addressed cache
boundary used for toolchains; loading and status inspection are read-only.
"""

from __future__ import annotations

from dataclasses import asdict
import hashlib
from pathlib import Path
import re
import tomllib
from urllib.parse import urlparse

from .toolchain_cache import acquire_pinned, import_pinned, inspect_cached

SOURCE_PACK_SCHEMA = "fidb-source-pack/v1"
SOURCE_STATUS_SCHEMA = "fidb-source-pack-status/v1"
MANAGED_SOURCE_ROOT = Path("var/fidb-sources")
MANAGED_SOURCE_DOWNLOADS = MANAGED_SOURCE_ROOT / "downloads"

_TOKEN = re.compile(r"^[a-z0-9][a-z0-9._+-]*$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PACK_FIELDS = {
    "schema_version",
    "id",
    "label",
    "language_id",
    "study_path",
    "selection_date",
    "release_policy",
    "source",
}
_SOURCE_FIELDS = {
    "rank",
    "id",
    "label",
    "version",
    "release_page",
    "url",
    "sha256",
    "download_bytes",
    "filename",
    "source_directory",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _required_fields(row: dict[str, object], expected: set[str], label: str) -> None:
    missing = sorted(expected - row.keys())
    extra = sorted(row.keys() - expected)
    if missing or extra:
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("unknown " + ", ".join(extra))
        raise ValueError(f"{label} fields are invalid: {'; '.join(details)}")


def _safe_token(value: object, label: str) -> str:
    token = str(value)
    if _TOKEN.fullmatch(token) is None:
        raise ValueError(f"{label} must be a lowercase safe token")
    return token


def _https_url(value: object, label: str) -> str:
    url = str(value)
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username:
        raise ValueError(f"{label} must be an HTTPS URL without credentials")
    return url


def _safe_relative_file(value: object, label: str) -> str:
    text = str(value)
    path = Path(text)
    if not text or path.is_absolute() or len(path.parts) != 1 or path.name != text:
        raise ValueError(f"{label} must be one safe relative path component")
    if text in {".", ".."} or "\x00" in text:
        raise ValueError(f"{label} must be one safe relative path component")
    return text


def load_source_pack(path: Path) -> dict[str, object]:
    """Load one strict source-pack authority without inspecting local state."""

    document = tomllib.loads(path.read_text(encoding="utf-8"))
    _required_fields(document, _PACK_FIELDS, "source pack")
    if document["schema_version"] != SOURCE_PACK_SCHEMA:
        raise ValueError("unsupported source pack schema")
    pack_id = _safe_token(document["id"], "source pack id")
    if not str(document["label"]).strip():
        raise ValueError("source pack label must be non-empty")
    if document["language_id"] != "c":
        raise ValueError("source pack language_id must be c")
    study_path = Path(str(document["study_path"]))
    if study_path.is_absolute() or ".." in study_path.parts:
        raise ValueError("source pack study_path must stay inside the project")
    for field in ("selection_date", "release_policy"):
        if not str(document[field]).strip():
            raise ValueError(f"source pack {field} must be non-empty")

    raw_sources = document["source"]
    if not isinstance(raw_sources, list) or not raw_sources:
        raise ValueError("source pack must contain at least one source")
    sources: list[dict[str, object]] = []
    ids: set[str] = set()
    ranks: set[int] = set()
    filenames: set[str] = set()
    for raw in raw_sources:
        if not isinstance(raw, dict):
            raise ValueError("source pack source rows must be tables")
        _required_fields(raw, _SOURCE_FIELDS, "source pack source")
        source_id = _safe_token(raw["id"], "source id")
        rank = raw["rank"]
        if not isinstance(rank, int) or rank < 1:
            raise ValueError(f"source {source_id} rank must be a positive integer")
        if source_id in ids or rank in ranks:
            raise ValueError("source pack ids and ranks must be unique")
        ids.add(source_id)
        ranks.add(rank)
        filename = _safe_relative_file(raw["filename"], f"source {source_id} filename")
        source_directory = _safe_relative_file(
            raw["source_directory"], f"source {source_id} source_directory"
        )
        if filename in filenames:
            raise ValueError("source pack filenames must be unique")
        filenames.add(filename)
        digest = str(raw["sha256"])
        if _DIGEST.fullmatch(digest) is None:
            raise ValueError(f"source {source_id} has invalid sha256")
        byte_count = raw["download_bytes"]
        if not isinstance(byte_count, int) or byte_count < 1:
            raise ValueError(f"source {source_id} download_bytes must be positive")
        label = str(raw["label"])
        version = str(raw["version"])
        if not label.strip() or not version.strip():
            raise ValueError(f"source {source_id} label and version must be non-empty")
        url = _https_url(raw["url"], f"source {source_id} url")
        release_page = _https_url(
            raw["release_page"], f"source {source_id} release_page"
        )
        sources.append(
            {
                **raw,
                "id": source_id,
                "rank": rank,
                "filename": filename,
                "source_directory": source_directory,
                "sha256": digest,
                "download_bytes": byte_count,
                "url": url,
                "release_page": release_page,
            }
        )
    if ranks != set(range(1, len(sources) + 1)):
        raise ValueError("source pack ranks must be contiguous from one")
    sources.sort(key=lambda row: int(row["rank"]))
    return {
        **document,
        "id": pack_id,
        "study_path": str(study_path),
        "source": sources,
        "catalog_path": str(path.resolve()),
        "catalog_sha256": _sha256(path),
    }


def select_sources(
    sources: list[dict[str, object]], requested: tuple[str, ...]
) -> list[dict[str, object]]:
    if not requested:
        return sources
    duplicates = sorted({item for item in requested if requested.count(item) > 1})
    if duplicates:
        raise ValueError("duplicate source id: " + ", ".join(duplicates))
    by_id = {str(row["id"]): row for row in sources}
    unknown = sorted(set(requested) - by_id.keys())
    if unknown:
        raise ValueError("unknown reviewed source id: " + ", ".join(unknown))
    return [by_id[item] for item in requested]


def source_pack_status(
    project_root: Path,
    pack_path: Path,
    requested: tuple[str, ...] = (),
) -> dict[str, object]:
    pack = load_source_pack(pack_path)
    selected = select_sources(pack["source"], requested)  # type: ignore[arg-type]
    downloads = project_root / MANAGED_SOURCE_DOWNLOADS
    rows = []
    for source in selected:
        inspection = inspect_cached(downloads, str(source["sha256"]))
        values = asdict(inspection)
        values["path"] = str(inspection.path)
        rows.append({**source, "cache": values})
    verified = sum(row["cache"]["state"] == "verified-cached" for row in rows)
    return {
        "schema_version": SOURCE_STATUS_SCHEMA,
        "pack_id": pack["id"],
        "pack_label": pack["label"],
        "catalog_path": pack["catalog_path"],
        "catalog_sha256": pack["catalog_sha256"],
        "managed_downloads": str(downloads),
        "summary": {
            "selected_sources": len(rows),
            "verified_cached_sources": verified,
            "missing_or_broken_sources": len(rows) - verified,
            "download_bytes": sum(int(row["download_bytes"]) for row in rows),
            "ready": verified == len(rows),
        },
        "sources": rows,
    }


def pull_source_pack(
    project_root: Path,
    pack_path: Path,
    requested: tuple[str, ...] = (),
) -> dict[str, object]:
    """Acquire selected reviewed archives sequentially and verify exact size."""

    pack = load_source_pack(pack_path)
    selected = select_sources(pack["source"], requested)  # type: ignore[arg-type]
    downloads = project_root / MANAGED_SOURCE_DOWNLOADS
    acquisitions = []
    for source in selected:
        result = acquire_pinned(str(source["url"]), str(source["sha256"]), downloads)
        if result.bytes != int(source["download_bytes"]):
            raise ValueError(
                f"reviewed size mismatch for {source['id']}: expected "
                f"{source['download_bytes']}, observed {result.bytes}"
            )
        values = asdict(result)
        values["path"] = str(result.path)
        values["quarantined"] = (
            str(result.quarantined) if result.quarantined is not None else None
        )
        acquisitions.append({"source_id": source["id"], **values})
    status = source_pack_status(project_root, pack_path, requested)
    status["operation"] = "pull"
    status["acquisitions"] = acquisitions
    return status


def import_source_archive(
    project_root: Path,
    pack_path: Path,
    source_id: str,
    archive: Path,
) -> dict[str, object]:
    """Verify and import one reviewed local archive without extracting it."""

    pack = load_source_pack(pack_path)
    selected = select_sources(pack["source"], (source_id,))  # type: ignore[arg-type]
    source = selected[0]
    observed_bytes = archive.stat().st_size
    if observed_bytes != int(source["download_bytes"]):
        raise ValueError(
            f"reviewed size mismatch for {source_id}: expected "
            f"{source['download_bytes']}, observed {observed_bytes}"
        )
    result = import_pinned(
        archive, str(source["sha256"]), project_root / MANAGED_SOURCE_DOWNLOADS
    )
    status = source_pack_status(project_root, pack_path, (source_id,))
    status["operation"] = "import"
    values = asdict(result)
    values["path"] = str(result.path)
    values["quarantined"] = (
        str(result.quarantined) if result.quarantined is not None else None
    )
    status["acquisitions"] = [{"source_id": source_id, **values}]
    return status
