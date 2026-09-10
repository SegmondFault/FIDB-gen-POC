"""Host-scoped emulator providers with reviewed managed and external inputs."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import tempfile
import tomllib
from typing import Mapping

from .toolchain_cache import CacheError, acquire_pinned, inspect_cached

REGISTRY_SCHEMA = "fidb-emulator-registry/v1"
LOCAL_SCHEMA = "fidb-emulator-local/v1"
STATUS_SCHEMA = "fidb-emulator-status/v1"
PREPARATION_SCHEMA = "fidb-emulator-preparation/v1"
MANAGED_ROOT = Path("var/fidb-emulators")
_MANIFEST = ".fidb-emulator-prepared.json"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_PROVIDER_FIELDS = {
    "id",
    "label",
    "engine",
    "mode",
    "version",
    "host_os",
    "host_architecture",
    "url",
    "sha256",
    "download_bytes",
    "installed_bytes",
    "archive_format",
    "bin_directory",
    "license_directory",
    "upstream_authority",
    "package_authority",
    "signature_url",
    "signature_primary_fingerprint",
    "signature_review",
    "license_ids",
}


class EmulatorProviderError(RuntimeError):
    """A reviewed emulator provider could not be resolved or prepared."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _host_identity() -> tuple[str, str]:
    systems = {"linux": "linux", "darwin": "macos", "windows": "windows"}
    architectures = {
        "amd64": "x86_64",
        "x86_64": "x86_64",
        "arm64": "aarch64",
        "aarch64": "aarch64",
    }
    system = systems.get(platform.system().lower(), platform.system().lower())
    machine = platform.machine().lower()
    return system, architectures.get(machine, machine)


def _safe_relative(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{field} must be a non-empty relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{field} must be a normalized relative path")
    return value


def load_emulator_registry(project_root: str | Path) -> dict[str, object]:
    root = Path(project_root).resolve()
    path = root / "emulators/registry.toml"
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if set(document) != {"schema_version", "qemu_user_targets", "managed_provider"}:
        raise ValueError("emulator registry has unsupported fields")
    if document.get("schema_version") != REGISTRY_SCHEMA:
        raise ValueError("emulator registry has an unsupported schema")

    targets = document.get("qemu_user_targets")
    if not isinstance(targets, dict) or not targets:
        raise ValueError("emulator registry requires qemu_user_targets")
    clean_targets: dict[str, str] = {}
    for target, executable in targets.items():
        if not isinstance(target, str) or _ID.fullmatch(target) is None:
            raise ValueError("emulator target ids must be stable lowercase identifiers")
        clean_targets[target] = _safe_relative(
            executable, f"qemu_user_targets.{target}"
        )

    raw_providers = document.get("managed_provider")
    if not isinstance(raw_providers, list) or not raw_providers:
        raise ValueError("emulator registry requires at least one managed provider")
    providers: list[dict[str, object]] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_providers):
        if not isinstance(raw, dict) or set(raw) != _PROVIDER_FIELDS:
            unknown = (
                sorted(set(raw) - _PROVIDER_FIELDS) if isinstance(raw, dict) else []
            )
            missing = (
                sorted(_PROVIDER_FIELDS - set(raw)) if isinstance(raw, dict) else []
            )
            raise ValueError(
                f"managed provider {index} has missing {missing} and unknown {unknown}"
            )
        row = dict(raw)
        provider_id = row.get("id")
        if not isinstance(provider_id, str) or _ID.fullmatch(provider_id) is None:
            raise ValueError(f"managed provider {index} has an invalid id")
        if provider_id in seen:
            raise ValueError(f"duplicate managed emulator provider: {provider_id}")
        seen.add(provider_id)
        for field in _PROVIDER_FIELDS - {
            "download_bytes",
            "installed_bytes",
            "license_ids",
        }:
            if not isinstance(row[field], str) or not row[field]:
                raise ValueError(f"managed provider {provider_id} {field} is invalid")
        if row["engine"] != "qemu" or row["mode"] != "user":
            raise ValueError(f"managed provider {provider_id} has unsupported mode")
        if not str(row["url"]).startswith("https://"):
            raise ValueError(f"managed provider {provider_id} URL must use HTTPS")
        if _DIGEST.fullmatch(str(row["sha256"])) is None:
            raise ValueError(f"managed provider {provider_id} has an invalid SHA-256")
        for field in ("download_bytes", "installed_bytes"):
            if not isinstance(row[field], int) or int(row[field]) <= 0:
                raise ValueError(f"managed provider {provider_id} {field} is invalid")
        licenses = row["license_ids"]
        if (
            not isinstance(licenses, list)
            or not licenses
            or not all(isinstance(item, str) and item for item in licenses)
        ):
            raise ValueError(f"managed provider {provider_id} license_ids is invalid")
        row["bin_directory"] = _safe_relative(
            row["bin_directory"], f"managed provider {provider_id} bin_directory"
        )
        row["license_directory"] = _safe_relative(
            row["license_directory"],
            f"managed provider {provider_id} license_directory",
        )
        providers.append(row)
    return {
        "schema_version": REGISTRY_SCHEMA,
        "authority_path": str(path.relative_to(root)),
        "qemu_user_targets": clean_targets,
        "managed_providers": providers,
    }


def _select_managed(
    registry: dict[str, object], provider_id: str | None = None
) -> dict[str, object]:
    host_os, host_architecture = _host_identity()
    providers = list(registry["managed_providers"])
    if provider_id is not None:
        selected = [row for row in providers if row["id"] == provider_id]
        if not selected:
            raise ValueError(f"unknown managed emulator provider: {provider_id}")
        provider = selected[0]
        if (
            provider["host_os"] != host_os
            or provider["host_architecture"] != host_architecture
        ):
            raise EmulatorProviderError(
                f"provider {provider_id} requires {provider['host_os']}/"
                f"{provider['host_architecture']}; detected {host_os}/{host_architecture}"
            )
        return provider
    matches = [
        row
        for row in providers
        if row["host_os"] == host_os and row["host_architecture"] == host_architecture
    ]
    if len(matches) != 1:
        raise EmulatorProviderError(
            f"detected {host_os}/{host_architecture} has {len(matches)} matching managed "
            "emulator providers; configure emulators/local.toml or select one explicitly"
        )
    return matches[0]


def _validate_archive_listing(archive: Path) -> None:
    bsdtar = shutil.which("bsdtar")
    if bsdtar is None:
        raise EmulatorProviderError(
            "managed arch-pkg-tar-zstd preparation requires bsdtar; an external "
            "QEMU installation can instead be selected in emulators/local.toml"
        )
    listing = subprocess.run(
        [bsdtar, "-tf", str(archive)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    verbose = subprocess.run(
        [bsdtar, "-tvf", str(archive)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    if not listing or len(listing) != len(verbose):
        raise EmulatorProviderError("emulator archive listing is empty or inconsistent")
    for name, description in zip(listing, verbose):
        _safe_relative(name.rstrip("/"), "emulator archive member")
        if not description or description[0] not in {"-", "d"}:
            raise EmulatorProviderError(
                f"emulator archive contains a link or special member: {name}"
            )


def _prepared_status(
    root: Path, provider: Mapping[str, object], targets: Mapping[str, str]
) -> dict[str, object]:
    digest = str(provider["sha256"])
    destination = root / MANAGED_ROOT / "prepared" / digest
    manifest_path = destination / _MANIFEST
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        manifest = None
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != PREPARATION_SCHEMA
    ):
        return {"state": "missing", "root": str(destination)}
    if (
        manifest.get("provider_id") != provider["id"]
        or manifest.get("sha256") != digest
    ):
        return {"state": "broken", "root": str(destination)}
    bin_root = destination / str(provider["bin_directory"])
    missing = [
        target
        for target, name in targets.items()
        if not (bin_root / name).is_file() or not os.access(bin_root / name, os.X_OK)
    ]
    return {
        "state": "prepared" if not missing else "broken",
        "root": str(destination),
        "bin_root": str(bin_root),
        "missing_targets": missing,
        "manifest": manifest,
    }


def prepare_managed_provider(
    project_root: str | Path, provider_id: str | None = None
) -> dict[str, object]:
    root = Path(project_root).resolve()
    registry = load_emulator_registry(root)
    provider = _select_managed(registry, provider_id)
    targets = dict(registry["qemu_user_targets"])
    downloads = root / MANAGED_ROOT / "downloads"
    acquired = acquire_pinned(
        str(provider["url"]),
        str(provider["sha256"]),
        downloads,
        max_bytes=int(provider["download_bytes"]),
    )
    if acquired.bytes != int(provider["download_bytes"]):
        raise EmulatorProviderError(
            "reviewed emulator archive byte count does not match the authority"
        )

    prepared_root = root / MANAGED_ROOT / "prepared"
    prepared_root.mkdir(parents=True, exist_ok=True)
    destination = prepared_root / str(provider["sha256"])
    lock_root = root / MANAGED_ROOT / "locks"
    lock_root.mkdir(parents=True, exist_ok=True)
    with (lock_root / f"prepare-{provider['sha256']}.lock").open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        current = _prepared_status(root, provider, targets)
        if current["state"] == "prepared":
            return {
                "schema_version": STATUS_SCHEMA,
                "operation": "pull",
                "cache_hit": True,
                "provider": provider,
                "preparation": current,
            }
        if destination.exists():
            quarantine = root / MANAGED_ROOT / "quarantine-prepared"
            quarantine.mkdir(parents=True, exist_ok=True)
            os.replace(destination, quarantine / f"{provider['sha256']}.{os.getpid()}")

        _validate_archive_listing(acquired.path)
        staging = Path(
            tempfile.mkdtemp(prefix=f".{provider['sha256']}.", dir=prepared_root)
        )
        try:
            bsdtar = shutil.which("bsdtar")
            assert bsdtar is not None
            subprocess.run(
                [
                    bsdtar,
                    "-xf",
                    str(acquired.path),
                    "-C",
                    str(staging),
                    "--no-same-owner",
                    "--no-same-permissions",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            bin_root = staging / str(provider["bin_directory"])
            executable_digests: dict[str, str] = {}
            for name in sorted(set(targets.values())):
                executable = bin_root / name
                if not executable.is_file():
                    raise EmulatorProviderError(
                        f"managed emulator package is missing {name}"
                    )
            for executable in sorted(bin_root.glob("qemu-*-static")):
                if not executable.is_file():
                    continue
                executable.chmod(0o755)
                executable_digests[executable.name] = _sha256(executable)
            license_root = staging / str(provider["license_directory"])
            if not license_root.is_dir():
                raise EmulatorProviderError(
                    "managed emulator package omits its licenses"
                )
            manifest = {
                "schema_version": PREPARATION_SCHEMA,
                "provider_id": provider["id"],
                "sha256": provider["sha256"],
                "archive_bytes": acquired.bytes,
                "installed_bytes": sum(
                    path.stat().st_size for path in staging.rglob("*") if path.is_file()
                ),
                "executable_sha256": executable_digests,
            }
            (staging / _MANIFEST).write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            os.replace(staging, destination)
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise
    return {
        "schema_version": STATUS_SCHEMA,
        "operation": "pull",
        "cache_hit": acquired.cache_hit,
        "provider": provider,
        "preparation": _prepared_status(root, provider, targets),
    }


def _probe_executables(
    bin_root: Path, executables: Mapping[str, str]
) -> tuple[dict[str, object], list[str]]:
    rows: dict[str, object] = {}
    missing: list[str] = []
    for target, name in sorted(executables.items()):
        path = (bin_root / name).resolve()
        if not path.is_file() or not os.access(path, os.X_OK):
            missing.append(target)
            rows[target] = {"state": "missing", "path": str(path)}
            continue
        result = subprocess.run(
            [str(path), "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        first_line = (result.stdout or result.stderr).splitlines()
        rows[target] = {
            "state": "ready" if result.returncode == 0 else "broken",
            "path": str(path),
            "sha256": _sha256(path),
            "version": first_line[0] if first_line else "",
        }
        if result.returncode != 0:
            missing.append(target)
    return rows, missing


def _external_status(
    root: Path, registry: dict[str, object], *, probe: bool
) -> dict[str, object] | None:
    local_path = root / "emulators/local.toml"
    if not local_path.is_file():
        return None
    document = tomllib.loads(local_path.read_text(encoding="utf-8"))
    required = {"schema_version", "provider", "engine", "mode", "root", "executables"}
    if set(document) != required or document.get("schema_version") != LOCAL_SCHEMA:
        raise ValueError("emulators/local.toml has unsupported schema or fields")
    if document.get("provider") != "external":
        raise ValueError("emulators/local.toml provider must be external")
    if document.get("engine") != "qemu" or document.get("mode") != "user":
        raise ValueError("emulators/local.toml supports QEMU user mode only")
    bin_root = Path(str(document["root"])).expanduser().resolve()
    raw_executables = document["executables"]
    known = dict(registry["qemu_user_targets"])
    if not isinstance(raw_executables, dict) or not raw_executables:
        raise ValueError("emulators/local.toml requires executable mappings")
    unknown = sorted(set(raw_executables) - set(known))
    if unknown:
        raise ValueError(
            "emulators/local.toml has unknown targets: " + ", ".join(unknown)
        )
    executables = {
        target: _safe_relative(name, f"executables.{target}")
        for target, name in raw_executables.items()
    }
    if probe:
        rows, missing = _probe_executables(bin_root, executables)
    else:
        rows = {
            target: {"path": str((bin_root / name).resolve())}
            for target, name in sorted(executables.items())
        }
        missing = [
            target
            for target, name in executables.items()
            if not (bin_root / name).is_file()
            or not os.access(bin_root / name, os.X_OK)
        ]
    return {
        "schema_version": STATUS_SCHEMA,
        "provider_kind": "external",
        "provider_id": "local-qemu-user",
        "authority_path": str(local_path.relative_to(root)),
        "host": dict(zip(("os", "architecture"), _host_identity())),
        "state": "ready" if not missing else "blocked",
        "bin_root": str(bin_root),
        "targets": rows,
        "missing_targets": missing,
    }


def emulator_status(
    project_root: str | Path, *, probe: bool = False
) -> dict[str, object]:
    root = Path(project_root).resolve()
    registry = load_emulator_registry(root)
    external = _external_status(root, registry, probe=probe)
    if external is not None:
        return external
    host_os, host_architecture = _host_identity()
    matches = [
        row
        for row in registry["managed_providers"]
        if row["host_os"] == host_os and row["host_architecture"] == host_architecture
    ]
    if not matches:
        return {
            "schema_version": STATUS_SCHEMA,
            "provider_kind": None,
            "host": {"os": host_os, "architecture": host_architecture},
            "state": "unavailable",
            "message": (
                "no matching managed provider; configure an external installation "
                "in emulators/local.toml or dispatch to a compatible worker"
            ),
        }
    provider = _select_managed(registry)
    cache = inspect_cached(root / MANAGED_ROOT / "downloads", str(provider["sha256"]))
    preparation = _prepared_status(root, provider, dict(registry["qemu_user_targets"]))
    result: dict[str, object] = {
        "schema_version": STATUS_SCHEMA,
        "provider_kind": "managed",
        "provider_id": provider["id"],
        "authority_path": registry["authority_path"],
        "host": {"os": host_os, "architecture": host_architecture},
        "state": "ready" if preparation["state"] == "prepared" else "missing",
        "cache": {
            "state": cache.state,
            "path": str(cache.path),
            "bytes": cache.bytes,
            "observed_sha256": cache.observed_sha256,
        },
        "preparation": preparation,
    }
    if probe and preparation["state"] == "prepared":
        rows, missing = _probe_executables(
            Path(str(preparation["bin_root"])),
            dict(registry["qemu_user_targets"]),
        )
        result["targets"] = rows
        result["missing_targets"] = missing
        result["state"] = "ready" if not missing else "blocked"
    return result


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="fidb-poc emulator",
        description="Inspect or acquire a host-compatible emulator provider.",
    )
    parser.add_argument("command", choices=("status", "pull"))
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--provider", help="explicit reviewed managed provider id")
    parser.add_argument(
        "--probe", action="store_true", help="execute version and digest probes"
    )
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "pull":
            document = prepare_managed_provider(
                arguments.project_root, arguments.provider
            )
        else:
            document = emulator_status(arguments.project_root, probe=arguments.probe)
        print(json.dumps(document, indent=2, sort_keys=True))
        return (
            0
            if document.get("state", document.get("preparation", {}).get("state"))
            in {"ready", "prepared"}
            else 1
        )
    except (
        CacheError,
        EmulatorProviderError,
        OSError,
        ValueError,
        subprocess.SubprocessError,
    ) as error:
        print(f"error: {error}", file=os.sys.stderr)
        return 1
