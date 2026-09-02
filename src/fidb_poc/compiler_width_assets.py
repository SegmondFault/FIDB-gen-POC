"""Expand the compact compiler-width TOML into pack, route and probe rows."""

from __future__ import annotations

from pathlib import Path
import tomllib


SCHEMA = "fidb-compiler-width-assets/v1"


def _rows(document: dict[str, object], key: str) -> list[dict[str, object]]:
    value = document.get(key)
    if not isinstance(value, list) or not value or not all(
        isinstance(row, dict) for row in value
    ):
        raise ValueError(f"compiler-width authority requires {key} rows")
    return [dict(row) for row in value]


def _unique(rows: list[dict[str, object]], key: str, context: str) -> None:
    values = [str(row[key]) for row in rows]
    if len(values) != len(set(values)):
        raise ValueError(f"compiler-width authority has duplicate {context}")


def load_compiler_width_assets(path: str | Path) -> dict[str, object]:
    document = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    allowed = {
        "schema_version",
        "host_system",
        "host_architecture",
        "purpose",
        "gcc_generation",
        "gcc_target",
        "gcc_asset",
        "llvm_mingw_asset",
        "selection",
    }
    if set(document) != allowed or document.get("schema_version") != SCHEMA:
        raise ValueError("compiler-width authority has unsupported schema/fields")
    for key in ("host_system", "host_architecture", "purpose"):
        if not isinstance(document[key], str) or not document[key]:
            raise ValueError(f"compiler-width {key} must be non-empty")
    generations = _rows(document, "gcc_generation")
    targets = _rows(document, "gcc_target")
    assets = _rows(document, "gcc_asset")
    mingw_assets = _rows(document, "llvm_mingw_asset")
    _unique(generations, "id", "GCC generation id")
    _unique(targets, "id", "GCC target id")
    generations_by_id = {str(row["id"]): row for row in generations}
    targets_by_id = {str(row["id"]): row for row in targets}
    expected_pairs = {
        (target_id, generation_id)
        for target_id in targets_by_id
        for generation_id in generations_by_id
    }
    observed_pairs = {
        (str(row.get("target")), str(row.get("generation"))) for row in assets
    }
    if observed_pairs != expected_pairs:
        raise ValueError("compiler-width GCC assets do not form the selected cross product")

    packs: list[dict[str, object]] = []
    routes: list[dict[str, object]] = []
    qualifications: list[dict[str, object]] = []
    for asset in assets:
        target = targets_by_id[str(asset["target"])]
        generation = generations_by_id[str(asset["generation"])]
        release = str(generation["release"])
        archive_suffix = str(generation["archive_suffix"])
        slug = str(target["id"])
        archive_root = f"{slug}--glibc--stable-{release}"
        pack_id = f"bootlin-{slug}-glibc-stable-{release}"
        compiler_id = str(generation["compiler_id"])
        compiler_version = compiler_id.removeprefix("gcc-")
        major = compiler_version.split(".", 1)[0]
        driver_prefix = str(target["driver_prefix"])
        route_id = f"{target['route_prefix']}-{major}"
        url_root = (
            "https://toolchains.bootlin.com/downloads/releases/toolchains/"
            f"{slug}"
        )
        packs.append(
            {
                "id": pack_id,
                "label": f"Bootlin {slug} glibc stable {release}",
                "kind": "compiler-sysroot",
                "target_ids": [target["target_id"]],
                "compiler_family": "gcc",
                "compiler_version": compiler_version,
                "compiler_driver": f"{driver_prefix}-gcc",
                "linker_family": "GNU binutils",
                "linker_version": str(generation["linker_version"]),
                "runtime": "glibc",
                "runtime_version": str(generation["runtime_version"]),
                "url": f"{url_root}/tarballs/{archive_root}.{archive_suffix}",
                "sha256": str(asset["sha256"]),
                "download_bytes": int(asset["download_bytes"]),
                "installed_bytes_estimate": int(asset["installed_bytes_estimate"]),
                "size_evidence": "measured-local-extraction-2026-09-02",
                "license_ids": [
                    "GPL-3.0-or-later",
                    "LGPL-2.1-or-later",
                    "various-open-source",
                ],
                "upstream_release": f"toolchains.bootlin.com-{release.rsplit('-', 1)[0]}.1",
                "upstream_authority": f"{url_root}/readmes/{archive_root}.txt",
                "archive_root": archive_root,
            }
        )
        routes.append(
            {
                "id": route_id,
                "label": f"{target['label']} · GCC {compiler_version}",
                "target_id": target["target_id"],
                "compiler_id": compiler_id,
                "coverage_requirement_id": target["coverage_requirement_id"],
                "compiler_family": "gcc",
                "target_triple": target["target_triple"],
                "evidence_role": "primary",
                "provisioning": "downloadable-pack",
                "pack_ids": [pack_id],
                "input_ids": [],
                "worker_class": "linux-x86_64",
                "qualification_state": "acquisition-reviewed",
                "additional_installed_bytes_estimate": 0,
                "additional_size_evidence": "none",
                "external_requirements": [],
            }
        )
        qualifications.append(
            {
                "id": route_id,
                "route_id": route_id,
                "tool_source": "pack",
                "tool_pack_id": pack_id,
                "driver_pattern": f"bin/{driver_prefix}-gcc",
                "cxx_driver_pattern": f"bin/{driver_prefix}-g++",
                "archiver_pattern": f"bin/{driver_prefix}-ar",
                "version_contains": compiler_version,
                "smoke_languages": ["c", "cpp"],
                "composition": "none",
            }
        )

    for asset in mingw_assets:
        release = str(asset["release"])
        compiler_id = str(asset["compiler_id"])
        compiler_version = compiler_id.removeprefix("llvm-clang-")
        major = compiler_version.split(".", 1)[0]
        archive_root = (
            f"llvm-mingw-{release}-ucrt-ubuntu-{asset['ubuntu']}-x86_64"
        )
        pack_id = f"llvm-mingw-ucrt-x86-64-linux-{release}"
        route_id = f"windows-x86-64-llvm-mingw-clang-{major}"
        packs.append(
            {
                "id": pack_id,
                "label": f"llvm-mingw UCRT {release} · Linux x86-64 host",
                "kind": "compiler-sysroot",
                "target_ids": ["windows-x86-64-pecoff"],
                "compiler_family": "llvm-clang",
                "compiler_version": compiler_version,
                "compiler_driver": "x86_64-w64-mingw32-clang",
                "linker_family": "LLD",
                "linker_version": compiler_version,
                "runtime": "mingw-w64 UCRT",
                "runtime_version": f"{release} release snapshot",
                "url": (
                    "https://github.com/mstorsjo/llvm-mingw/releases/download/"
                    f"{release}/{archive_root}.tar.xz"
                ),
                "sha256": str(asset["sha256"]),
                "download_bytes": int(asset["download_bytes"]),
                "installed_bytes_estimate": int(asset["installed_bytes_estimate"]),
                "size_evidence": "measured-local-extraction-2026-09-02",
                "license_ids": [
                    "Apache-2.0-WITH-LLVM-exception",
                    "ZPL-2.1",
                    "various-open-source",
                ],
                "upstream_release": f"llvm-mingw-{release}-llvm-{compiler_version}",
                "upstream_authority": (
                    "https://github.com/mstorsjo/llvm-mingw/releases/tag/"
                    f"{release}"
                ),
                "archive_root": archive_root,
            }
        )
        routes.append(
            {
                "id": route_id,
                "label": f"Windows x86-64 · llvm-mingw Clang {compiler_version}",
                "target_id": "windows-x86-64-pecoff",
                "compiler_id": compiler_id,
                "coverage_requirement_id": "windows-x86-64-msvc",
                "compiler_family": "llvm-clang",
                "target_triple": "x86_64-w64-mingw32",
                "evidence_role": "cross-build",
                "provisioning": "downloadable-pack",
                "pack_ids": [pack_id],
                "input_ids": [],
                "worker_class": "linux-x86_64",
                "qualification_state": "acquisition-reviewed",
                "additional_installed_bytes_estimate": 0,
                "additional_size_evidence": "none",
                "external_requirements": [],
            }
        )
        qualifications.append(
            {
                "id": route_id,
                "route_id": route_id,
                "tool_source": "pack",
                "tool_pack_id": pack_id,
                "driver_pattern": "bin/x86_64-w64-mingw32-clang",
                "cxx_driver_pattern": "bin/x86_64-w64-mingw32-clang++",
                "archiver_pattern": "bin/llvm-ar",
                "version_contains": compiler_version,
                "smoke_languages": ["c", "cpp"],
                "composition": "none",
            }
        )

    selection = document.get("selection")
    if not isinstance(selection, dict):
        raise ValueError("compiler-width selection must be a table")
    return {
        "schema_version": SCHEMA,
        "host_system": document["host_system"],
        "host_architecture": document["host_architecture"],
        "purpose": document["purpose"],
        "gcc_generations": generations,
        "gcc_targets": targets,
        "selection": dict(selection),
        "packs": packs,
        "routes": routes,
        "qualifications": qualifications,
    }
