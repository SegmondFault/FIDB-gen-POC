"""Execute the reviewed C10 machine-validation campaign.

The production queue remains immutable.  This runner consumes sealed build
evidence, reconstructs the compacted OpenSSL archives when required, builds
never-executed fold composites, exports their FID hashes and performs a
leave-one-exact-identity-out owner comparison from a bounded SQLite index.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import tomllib
from typing import Iterable, Mapping

from .c_width import compile_c_width, materialize_width_configuration
from .machine_validation import compile_machine_validation
from .toolchain_packs import load_toolchain_pack_catalog, resolve_toolchain_profile


RUNTIME_SCHEMA = "fidb-machine-validation-runtime/v1"
RUN_STATUS_SCHEMA = "fidb-machine-validation-run-status/v1"
UNIT_RESULT_SCHEMA = "fidb-machine-validation-unit/v1"
REFERENCE_INDEX_SCHEMA = "fidb-machine-validation-reference-index/v3"
QUERY_COPY_POLICY = "debug-stripped-symbol-indexed"
DEFAULT_RUNTIME = Path("validation/machine-validation-runtime.toml")
PAUSE_REQUEST_NAME = "pause-request.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _inside(root: Path, value: str, label: str) -> Path:
    path = (root / value).expanduser().resolve() if not Path(value).is_absolute() else Path(value).resolve()
    if path != root and root not in path.parents:
        raise ValueError(f"{label} escapes the project root: {value}")
    return path


def _atomic_json(path: Path, document: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}-", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _result_documents(run_root: Path, mode: str) -> list[dict[str, object]]:
    documents = []
    for path in (run_root / "units").glob("*/result.json"):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if document.get("mode") == mode:
            documents.append(document)
    return documents


def _result_counts(run_root: Path, mode: str) -> tuple[int, int]:
    documents = _result_documents(run_root, mode)
    return (
        sum(row.get("state") == "complete" for row in documents),
        sum(row.get("state") == "failed" for row in documents),
    )


def _validation_process_active(pid: object, run_id: str) -> bool:
    """Reject stale PIDs and zombies without signalling an unrelated process."""
    if type(pid) is not int or pid < 1:
        return False
    process = Path("/proc") / str(pid)
    try:
        fields = (process / "stat").read_text(encoding="utf-8").split()
        command = (process / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", errors="replace")
    except OSError:
        return False
    return (
        len(fields) > 2 and fields[2] != "Z"
        and "machine-validation" in command and run_id in command
    )


def _terminate_worker_groups(processes: list[subprocess.Popen[bytes]]) -> None:
    """Stop validation sessions, including their Ghidra descendants."""
    live = [process for process in processes if process.poll() is None]
    for process in live:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 15
    for process in live:
        try:
            process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


def _archive_failed_result(result_path: Path) -> None:
    """Retain concise failure evidence before an explicit resume retries a unit."""
    if not result_path.is_file():
        return
    try:
        document = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if document.get("state") == "complete":
        return
    attempts = result_path.parent / "attempts"
    attempts.mkdir(parents=True, exist_ok=True)
    attempt = 1
    while (attempts / f"result-{attempt:03d}.json").exists():
        attempt += 1
    result_path.replace(attempts / f"result-{attempt:03d}.json")


def load_runtime(project_root: str | Path, authority: str | Path = DEFAULT_RUNTIME) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    path = _inside(root, str(authority), "machine-validation runtime")
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    expected = {
        "schema_version", "validation_id", "manifest", "schedule", "output_root",
        "ledger", "source_archive", "openssl_width_report", "ghidra_headless",
        "execution", "canary", "safety",
    }
    if set(document) != expected or document.get("schema_version") != RUNTIME_SCHEMA:
        raise ValueError("machine-validation runtime has unsupported fields or schema")
    execution = document["execution"]
    canary = document["canary"]
    safety = document["safety"]
    if set(execution) != {
        "workers", "build_jobs_per_cell", "jvm_initial_heap_mib", "jvm_max_heap_mib",
        "jvm_active_processors", "minimum_distinct_hashes", "max_failure_rows",
        "checkpoint_every_units", "retain_ghidra_projects_on_failure",
        "retain_ghidra_projects_on_success",
    }:
        raise ValueError("machine-validation execution policy has unexpected fields")
    if set(canary) != {"positions", "folds_by_position", "minimum_distinct_hashes", "require_formats"}:
        raise ValueError("machine-validation canary policy has unexpected fields")
    if set(safety) != {
        "execute_target_binaries", "require_production_queue_drained",
        "minimum_free_disk_gib", "minimum_available_memory_gib",
    }:
        raise ValueError("machine-validation safety policy has unexpected fields")
    for field in ("workers", "build_jobs_per_cell", "jvm_initial_heap_mib", "jvm_max_heap_mib", "jvm_active_processors", "minimum_distinct_hashes", "max_failure_rows", "checkpoint_every_units"):
        if type(execution[field]) is not int or execution[field] < 1:
            raise ValueError(f"machine-validation execution.{field} must be positive")
    if safety["execute_target_binaries"] is not False:
        raise ValueError("machine-validation must never execute target binaries")
    for field in ("manifest", "schedule", "output_root", "ledger", "source_archive", "openssl_width_report"):
        _inside(root, str(document[field]), field)
    headless = Path(str(document["ghidra_headless"])).resolve()
    if not headless.is_file() or not os.access(headless, os.X_OK):
        raise ValueError(f"configured Ghidra headless launcher is unavailable: {headless}")
    return {**document, "authority_path": str(path.relative_to(root)), "authority_sha256": _sha256(path)}


def _configuration(root: Path, recipe: str = "openssl@3.5.8"):
    catalog = load_toolchain_pack_catalog(root)
    width = compile_c_width(root, "c-width-v2", _catalog=catalog)
    route_plan = resolve_toolchain_profile(root, str(width["toolchain_profile"]), _catalog=catalog)
    return materialize_width_configuration(root, recipe, route_plan, _catalog=catalog)


def _manifest(root: Path, runtime: Mapping[str, object]) -> dict[str, object]:
    path = _inside(root, str(runtime["manifest"]), "validation manifest")
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if document.get("schema_version") != "fidb-machine-validation-batch/v1" or document.get("id") != runtime["validation_id"]:
        raise ValueError("machine-validation manifest identity does not match runtime")
    if document.get("state") != "materialized-disarmed" or document.get("execute_target_binaries") is not False:
        raise ValueError("machine-validation manifest is not safely materialized and disarmed")
    units = document.get("work_unit")
    if not isinstance(units, list) or len(units) != 222:
        raise ValueError("machine-validation manifest must contain exactly 222 work units")
    return document


def _queue_drained(root: Path, runtime: Mapping[str, object]) -> bool:
    path = _inside(root, str(runtime["ledger"]), "production ledger")
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
    try:
        count = connection.execute(
            "SELECT COUNT(*) FROM jobs WHERE active = 1 AND state IN ('queued','leased','running','failed')"
        ).fetchone()[0]
        return int(count) == 0
    finally:
        connection.close()


def _production_evidence(root: Path, runtime: Mapping[str, object], cohort: set[str]) -> tuple[dict, dict]:
    archives: dict[tuple[str, str, str], dict[str, object]] = {}
    signatures: dict[tuple[str, str, str], dict[str, object]] = {}
    ledger = _inside(root, str(runtime["ledger"]), "production ledger")
    connection = sqlite3.connect(f"file:{ledger}?mode=ro", uri=True, timeout=5)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            """
            SELECT jobs.job_id, jobs.result_json, cells.cell_json
            FROM jobs
            JOIN resolved_cells AS cells
              ON cells.plan_digest = jobs.plan_digest AND cells.cell_id = jobs.base_cell_id
            WHERE jobs.active = 1 AND jobs.state = 'complete'
            """
        )
        for row in rows:
            cell = json.loads(row["cell_json"])
            recipe = cell.get("recipe", {})
            owner = f'{recipe.get("name")}@{recipe.get("version")}'
            if owner not in cohort:
                continue
            route = str(cell.get("toolchain", {}).get("route", ""))
            treatment = str(cell.get("build", {}).get("treatment", ""))
            key = (owner, route, treatment)
            if key in signatures:
                raise ValueError(f"duplicate active production evidence for {key}")
            result = json.loads(row["result_json"])
            attempt = _inside(root, str(result["attempt_root"]), "attempt root")
            seal_path = _inside(root, str(result["seal"]["path"]), "cell seal")
            if _sha256(seal_path) != result["seal"]["sha256"]:
                raise ValueError(f"cell seal digest mismatch for {row['job_id']}")
            seal = json.loads(seal_path.read_text(encoding="utf-8"))
            archive_paths = [attempt / value for value in str(seal["evidence"]["static_archive_path"]).split(";")]
            archive_digests = str(seal["evidence"]["static_archive_sha256"]).split(";")
            if len(archive_paths) != len(archive_digests) or any(not path.is_file() for path in archive_paths):
                raise ValueError(f"retained static archives are incomplete for {key}")
            if any(_sha256(path) != digest for path, digest in zip(archive_paths, archive_digests, strict=True)):
                raise ValueError(f"retained static archive digest mismatch for {key}")
            signature_files = list((attempt / "artifacts/libs/fid-signatures").glob("*.jsonl"))
            if len(signature_files) != 1 or not signature_files[0].is_file():
                raise ValueError(f"retained signature evidence is incomplete for {key}")
            archives[key] = {
                "paths": archive_paths,
                "sha256": archive_digests,
                "source": str(attempt.relative_to(root)),
            }
            signatures[key] = {
                "path": signature_files[0],
                "sha256": _sha256(signature_files[0]),
                "source": str(signature_files[0].relative_to(root)),
            }
    finally:
        connection.close()
    return archives, signatures


def _width_openssl_signatures(root: Path, runtime: Mapping[str, object], expected: set[tuple[str, str, str]]) -> dict:
    report_path = _inside(root, str(runtime["openssl_width_report"]), "OpenSSL width report")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    expected_digests: dict[tuple[str, str], str] = {}
    for replay in report.get("replay_results", []):
        for cell in replay.get("cells", []):
            if cell.get("status") == "complete":
                expected_digests[(str(cell["route_id"]), str(cell["treatment_id"]))] = str(cell["fid_signatures_sha256"])
    base = report_path.parent / "replay-01"
    result = {}
    for key in expected:
        _owner, route, treatment = key
        digest = expected_digests.get((route, treatment))
        if digest is None:
            continue
        name = f"openssl-3.5.8-{route}-{treatment}.fid-signatures.jsonl"
        matches = list(base.glob(f"group-*/artifacts/libs/fid-signatures/{name}"))
        if len(matches) != 1 or _sha256(matches[0]) != digest:
            raise ValueError(f"OpenSSL width signature evidence is unavailable or changed for {route}:{treatment}")
        result[key] = {"path": matches[0], "sha256": digest, "source": str(matches[0].relative_to(root))}
    return result


def resolve_evidence(project_root: str | Path, runtime_path: str | Path = DEFAULT_RUNTIME) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    runtime = load_runtime(root, runtime_path)
    manifest = _manifest(root, runtime)
    status = compile_machine_validation(root)
    if not status["readiness"]["eligible"]:
        raise ValueError("machine-validation cohort is no longer eligible")
    cohort = set(status["randomization"]["canonical_ids"])
    expected = {
        (owner, str(unit["route_id"]), str(unit["treatment_id"]))
        for owner in cohort for unit in manifest["work_unit"]
    }
    archives, signatures = _production_evidence(root, runtime, cohort)
    signatures.update(_width_openssl_signatures(root, runtime, expected - set(signatures)))
    missing_signatures = expected - set(signatures)
    missing_archives = expected - set(archives)
    reconstructable = {key for key in missing_archives if key[0] == "openssl@3.5.8"}
    unrecoverable = missing_archives - reconstructable
    configuration = _configuration(root)
    routes = {route.id: route for route in configuration.routes}
    treatments = {treatment.id: treatment for treatment in configuration.treatments}
    missing_tools = []
    for unit in manifest["work_unit"]:
        route = routes.get(str(unit["route_id"]))
        treatment = treatments.get(str(unit["treatment_id"]))
        if route is None or treatment is None or not treatment.applies_to(route):
            missing_tools.append(str(unit["id"]))
            continue
        for command in (route.compiler, route.archiver, route.ranlib):
            if not Path(command[0]).is_file() or not os.access(command[0], os.X_OK):
                missing_tools.append(str(unit["id"]))
                break
    free_disk = shutil.disk_usage(root).free
    available_memory = _available_memory_bytes()
    blockers = []
    if missing_signatures:
        blockers.append(f"{len(missing_signatures)} signature inputs are missing")
    if unrecoverable:
        blockers.append(f"{len(unrecoverable)} static archive inputs are missing and unrecoverable")
    if missing_tools:
        blockers.append(f"{len(set(missing_tools))} work units lack executable reviewed tools")
    if runtime["safety"]["require_production_queue_drained"] and not _queue_drained(root, runtime):
        blockers.append("production queue is not drained")
    if free_disk < int(runtime["safety"]["minimum_free_disk_gib"]) * 1024**3:
        blockers.append("free disk is below the reviewed safety floor")
    if available_memory < int(runtime["safety"]["minimum_available_memory_gib"]) * 1024**3:
        blockers.append("available memory is below the reviewed safety floor")
    return {
        "runtime": runtime,
        "manifest": manifest,
        "status": status,
        "configuration": configuration,
        "archives": archives,
        "signatures": signatures,
        "summary": {
            "expected_inputs": len(expected),
            "sealed_archive_inputs": len(archives),
            "reconstructable_archive_inputs": len(reconstructable),
            "signature_inputs": len(signatures),
            "work_units": len(manifest["work_unit"]),
            "free_disk_bytes": free_disk,
            "available_memory_bytes": available_memory,
        },
        "blockers": blockers,
    }


def _available_memory_bytes() -> int:
    fields = {}
    for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        name, value = line.split(":", 1)
        fields[name] = int(value.strip().split()[0]) * 1024
    return fields.get("MemAvailable", 0)


def preflight(project_root: str | Path, runtime_path: str | Path = DEFAULT_RUNTIME) -> dict[str, object]:
    evidence = resolve_evidence(project_root, runtime_path)
    runtime = evidence["runtime"]
    return {
        "schema_version": "fidb-machine-validation-preflight/v1",
        "validation_id": runtime["validation_id"],
        "state": "ready" if not evidence["blockers"] else "blocked",
        "authority_path": runtime["authority_path"],
        "authority_sha256": runtime["authority_sha256"],
        "summary": evidence["summary"],
        "blockers": evidence["blockers"],
    }


def _run_root(root: Path, runtime: Mapping[str, object], run_id: str) -> Path:
    if not run_id or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for character in run_id):
        raise ValueError("machine-validation run id is not a safe path component")
    return _inside(root, f'{runtime["output_root"]}/{run_id}', "validation run")


def _strip_tool(route) -> Path:
    directory = Path(route.compiler[0]).parent
    compiler_name = Path(route.compiler[0]).name
    candidates = []
    if compiler_name.endswith("-gcc"):
        candidates.append(directory / f'{compiler_name[:-4]}-strip')
    if compiler_name.endswith("-clang"):
        candidates.append(directory / f'{compiler_name[:-6]}-strip')
    candidates.extend((directory / "llvm-strip", directory / "strip"))
    for path in candidates:
        if path.is_file() and os.access(path, os.X_OK):
            return path
    raise ValueError(f"no strip tool found beside compiler for {route.id}")


def _link_composite(route, archives: list[Path], output: Path, truth_map: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    def command(support: list[Path]) -> list[str]:
        if route.binary_format == "PE/COFF":
            return [
            *route.compiler, "-shared", "-nostdlib", "-Wl,/force:unresolved",
            "-Wl,/force:multiple", "-Wl,--whole-archive", *map(str, archives),
            "-Wl,--no-whole-archive", "-o", str(output),
            ]
        return [
            *route.compiler, "-nostdlib", "-no-pie", "-Wl,-e,0",
            "-Wl,--allow-multiple-definition", "-Wl,--unresolved-symbols=ignore-all",
            f"-Wl,-Map,{truth_map}", *map(str, support),
            "-Wl,--whole-archive", *map(str, archives),
            "-Wl,--no-whole-archive", "-o", str(output),
        ]

    result = subprocess.run(command([]), text=True, capture_output=True, timeout=900, check=False)
    log = result.stdout + result.stderr
    if (
        result.returncode != 0
        and route.binary_format == "ELF"
        and "__stack_chk_fail_local" in result.stderr
    ):
        source = output.parent / "stack-chk-fail-local.S"
        support = output.parent / "stack-chk-fail-local.o"
        source.write_text(
            ".text\n.globl __stack_chk_fail_local\n.hidden __stack_chk_fail_local\n"
            ".type __stack_chk_fail_local, %function\n__stack_chk_fail_local:\n"
            ".size __stack_chk_fail_local, .-__stack_chk_fail_local\n",
            encoding="utf-8",
        )
        compiled = subprocess.run(
            [*route.compiler, "-c", "-x", "assembler", str(source), "-o", str(support)],
            text=True, capture_output=True, timeout=120, check=False,
        )
        log += "\n--- validation stack-check support ---\n" + compiled.stdout + compiled.stderr
        if compiled.returncode == 0 and support.is_file():
            output.unlink(missing_ok=True)
            result = subprocess.run(
                command([support]), text=True, capture_output=True, timeout=900, check=False
            )
            log += "\n--- validation composite retry ---\n" + result.stdout + result.stderr
    (output.parent / "link.log").write_text(log, encoding="utf-8")
    if result.returncode != 0 or not output.is_file() or output.stat().st_size == 0:
        raise RuntimeError(f"composite link failed for {route.id}: {result.stderr[-2000:]}")
    return output


def _read_signature_rows(path: Path) -> Iterable[dict[str, object]]:
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"signature row is not an object: {path}")
            yield row


def build_reference_index(project_root: str | Path, evidence: Mapping[str, object], run_root: Path) -> Path:
    root = Path(project_root).resolve()
    path = run_root / "reference-index.sqlite3"
    input_digest = hashlib.sha256(
        json.dumps(
            sorted((list(key), value["sha256"]) for key, value in evidence["signatures"].items()),
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    if path.is_file():
        connection = sqlite3.connect(path)
        try:
            row = connection.execute("SELECT value FROM metadata WHERE key='input_digest'").fetchone()
            schema = connection.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()
            count = connection.execute(
                "SELECT COUNT(*) FROM reference_owner_signature"
            ).fetchone()[0]
            if row and row[0] == input_digest and schema and schema[0] == REFERENCE_INDEX_SCHEMA and count > 0:
                return path
        except sqlite3.Error:
            pass
        finally:
            connection.close()
        path.unlink()
    connection = sqlite3.connect(path)
    try:
        connection.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE reference_identity(
                language TEXT NOT NULL, target_os TEXT NOT NULL, binary_format TEXT NOT NULL,
                full_hash TEXT NOT NULL, specific_hash TEXT NOT NULL,
                additional_size INTEGER NOT NULL, code_size INTEGER NOT NULL,
                owner TEXT NOT NULL, route_id TEXT NOT NULL, treatment_id TEXT NOT NULL,
                function_name TEXT NOT NULL, evidence_path TEXT NOT NULL,
                PRIMARY KEY(
                    target_os, binary_format, language, full_hash, specific_hash,
                    additional_size, code_size, owner, route_id, treatment_id
                )
            ) WITHOUT ROWID;
            CREATE TABLE reference_owner_signature(
                language TEXT NOT NULL, target_os TEXT NOT NULL, binary_format TEXT NOT NULL,
                full_hash TEXT NOT NULL, specific_hash TEXT NOT NULL,
                additional_size INTEGER NOT NULL, code_size INTEGER NOT NULL,
                owner TEXT NOT NULL, function_name TEXT NOT NULL,
                evidence_path TEXT NOT NULL, identity_count INTEGER NOT NULL,
                PRIMARY KEY(
                    target_os, binary_format, language, full_hash, specific_hash,
                    additional_size, code_size, owner
                )
            ) WITHOUT ROWID;
        """)
        routes = {route.id: route for route in evidence["configuration"].routes}
        inserted = 0
        for (owner, route, treatment), item in sorted(evidence["signatures"].items()):
            route_authority = routes[route]
            batch = []
            for row in _read_signature_rows(item["path"]):
                batch.append((
                    str(row.get("language", row.get("ghidra_language_id", ""))),
                    route_authority.target_os, route_authority.binary_format,
                    str(row["full_hash"]), str(row["specific_hash"]),
                    int(row["specific_hash_additional_size"]), int(row["code_unit_size"]),
                    owner, route, treatment, str(row.get("name", row.get("function_name", ""))),
                    str(item["source"]),
                ))
                if len(batch) >= 5000:
                    before = connection.total_changes
                    connection.executemany(
                        "INSERT OR IGNORE INTO reference_identity VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        batch,
                    )
                    inserted += connection.total_changes - before
                    batch.clear()
            if batch:
                before = connection.total_changes
                connection.executemany(
                    "INSERT OR IGNORE INTO reference_identity VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    batch,
                )
                inserted += connection.total_changes - before
            connection.commit()
        connection.execute(
            """
            INSERT INTO reference_owner_signature
            SELECT language, target_os, binary_format, full_hash, specific_hash,
                   additional_size, code_size, owner, MIN(function_name),
                   MIN(evidence_path), COUNT(*)
            FROM reference_identity
            GROUP BY target_os, binary_format, language, full_hash, specific_hash,
                     additional_size, code_size, owner
            """
        )
        connection.execute("INSERT INTO metadata VALUES ('schema_version',?)", (REFERENCE_INDEX_SCHEMA,))
        connection.execute("INSERT INTO metadata VALUES ('input_digest',?)", (input_digest,))
        connection.execute("INSERT INTO metadata VALUES ('rows',?)", (str(inserted),))
        connection.commit()
    finally:
        connection.close()
    return path


def _query_index(
    index_path: Path,
    query_path: Path,
    route_id: str,
    treatment_id: str,
    target_os: str,
    binary_format: str,
    include_exact: bool,
) -> tuple[dict[str, set[str]], dict[str, dict[str, str]]]:
    connection = sqlite3.connect(index_path)
    try:
        connection.executescript("""
            CREATE TEMP TABLE query_signature(
                address TEXT, function_name TEXT, language TEXT, full_hash TEXT,
                specific_hash TEXT, additional_size INTEGER, code_size INTEGER
            );
        """)
        rows = [(
            str(row.get("address", "")), str(row.get("function_name", "")),
            str(row.get("ghidra_language_id", row.get("language", ""))),
            str(row["full_hash"]), str(row["specific_hash"]),
            int(row["specific_hash_additional_size"]), int(row["code_unit_size"]),
        ) for row in _read_signature_rows(query_path)]
        connection.executemany("INSERT INTO query_signature VALUES (?,?,?,?,?,?,?)", rows)
        exact_clause = "" if include_exact else """
            AND (
                reference.identity_count > 1
                OR NOT EXISTS (
                    SELECT 1
                    FROM reference_identity AS exact
                    WHERE exact.target_os=reference.target_os
                      AND exact.binary_format=reference.binary_format
                      AND exact.language=reference.language
                      AND exact.full_hash=reference.full_hash
                      AND exact.specific_hash=reference.specific_hash
                      AND exact.additional_size=reference.additional_size
                      AND exact.code_size=reference.code_size
                      AND exact.owner=reference.owner
                      AND exact.route_id=? AND exact.treatment_id=?
                )
            )
        """
        parameters = () if include_exact else (route_id, treatment_id)
        matches: dict[str, set[str]] = defaultdict(set)
        examples: dict[str, dict[str, str]] = {}
        sql = f"""
            SELECT query.address, query.function_name, reference.owner,
                   reference.function_name, reference.evidence_path,
                   query.full_hash, query.specific_hash, query.additional_size, query.code_size
            FROM query_signature AS query
            CROSS JOIN reference_owner_signature AS reference
              ON reference.target_os=? AND reference.binary_format=?
             AND reference.language=query.language AND reference.full_hash=query.full_hash
             AND reference.specific_hash=query.specific_hash
             AND reference.additional_size=query.additional_size AND reference.code_size=query.code_size
            WHERE 1=1 {exact_clause}
        """
        for row in connection.execute(sql, (target_os, binary_format, *parameters)):
            address, query_name, owner, corpus_name, evidence_path, full_hash, specific_hash, additional, size = row
            signature = f"{full_hash}:{specific_hash}:{additional}:{size}"
            matches[str(owner)].add(f"{address}:{signature}")
            examples.setdefault(str(owner), {
                "function_id": str(query_name or address), "signature": signature,
                "candidate_owner": str(owner), "evidence_path": str(evidence_path),
                "corpus_function": str(corpus_name),
            })
        return matches, examples
    finally:
        connection.close()


def _rebuild_openssl_archives(root: Path, evidence: Mapping[str, object], route, treatment, worker_root: Path) -> dict[str, object]:
    from .pipeline import build_library, detect_project, extract_source

    source_archive = _inside(root, str(evidence["runtime"]["source_archive"]), "OpenSSL source archive")
    configuration = evidence["configuration"]
    library = configuration.libraries[0]
    marker = worker_root / "source-root.txt"
    if not marker.is_file():
        extracted = worker_root / "extracted"
        source_root = extract_source(library, source_archive, extracted, verified=True)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(str(source_root), encoding="utf-8")
    else:
        source_root = Path(marker.read_text(encoding="utf-8"))
        if not source_root.is_dir():
            raise ValueError("cached OpenSSL validation source root is missing")
    detection = detect_project(library, source_root)
    work = worker_root / "work"
    record, _objects = build_library(
        library, route, treatment, detection, source_root, work, worker_root / "logs",
        build_jobs_per_cell=int(evidence["runtime"]["execution"]["build_jobs_per_cell"]),
    )
    if record.status != "built":
        raise RuntimeError(record.error or "OpenSSL archive reconstruction failed")
    paths = [(work.parent / value).resolve() for value in record.static_archive_path.split(";")]
    return {"paths": paths, "sha256": record.static_archive_sha256.split(";"), "source": "validation-rebuild"}


def _worker(project_root: str | Path, runtime_path: str | Path, run_id: str, positions: list[int], mode: str) -> int:
    root = Path(project_root).resolve()
    evidence = resolve_evidence(root, runtime_path)
    run_root = _run_root(root, evidence["runtime"], run_id)
    index = _inside(root, str(evidence["runtime"]["output_root"]), "validation output") / "reference-index.sqlite3"
    if not index.is_file():
        raise ValueError("machine-validation reference index is absent")
    configuration = evidence["configuration"]
    routes = {route.id: route for route in configuration.routes}
    treatments = {treatment.id: treatment for treatment in configuration.treatments}
    units = {int(unit["position"]): unit for unit in evidence["manifest"]["work_unit"]}
    fold_map = {"A": evidence["status"]["randomization"]["fold_a"], "B": evidence["status"]["randomization"]["fold_b"]}
    canary_folds = defaultdict(set)
    for item in evidence["runtime"]["canary"]["folds_by_position"]:
        position, fold = str(item).split(":", 1); canary_folds[int(position)].add(fold)
    os.environ["GHIDRA_HEADLESS"] = str(evidence["runtime"]["ghidra_headless"])
    execution = evidence["runtime"]["execution"]
    os.environ["_JAVA_OPTIONS"] = (
        f'-Xms{execution["jvm_initial_heap_mib"]}m -Xmx{execution["jvm_max_heap_mib"]}m '
        f'-XX:ActiveProcessorCount={execution["jvm_active_processors"]}'
    )
    from . import ghidra_fid
    from .pipeline import find_ghidra, ghidra_environment
    _headless, ghidra_home = find_ghidra()
    ghidra_fid.ensure_started(ghidra_home, ghidra_environment(run_root / f"worker-{os.getpid()}" / "ghidra-user"))
    for position in positions:
        unit = units[position]
        unit_root = run_root / "units" / f"{position:03d}-{unit['route_id']}-{unit['treatment_id']}"
        result_path = unit_root / "result.json"
        if result_path.is_file():
            previous = json.loads(result_path.read_text(encoding="utf-8"))
            if previous.get("state") == "complete":
                continue
            _archive_failed_result(result_path)
        route = routes[str(unit["route_id"])]
        treatment = treatments[str(unit["treatment_id"])]
        folds = sorted(canary_folds[position]) if mode == "canary" else ["A", "B"]
        fold_results = []
        started_ns = time.monotonic_ns()
        try:
            for fold in folds:
                fold_root = unit_root / f"fold-{fold}"
                owners = list(fold_map[fold])
                archive_items = []
                for owner in owners:
                    key = (owner, route.id, treatment.id)
                    item = evidence["archives"].get(key)
                    if item is None:
                        item = _rebuild_openssl_archives(root, evidence, route, treatment, run_root / f"worker-{os.getpid()}" / "openssl")
                        evidence["archives"][key] = item
                    archive_items.append((owner, item))
                truth = {
                    "schema_version": "fidb-machine-validation-truth-map/v1",
                    "fold": fold, "owners": owners, "route_id": route.id,
                    "treatment_id": treatment.id,
                    "archives": [
                        {"owner": owner, "paths": [str(path.relative_to(root)) for path in item["paths"]], "sha256": item["sha256"]}
                        for owner, item in archive_items
                    ],
                }
                _atomic_json(fold_root / "truth-map.json", truth)
                suffix = ".dll" if route.binary_format == "PE/COFF" else ".elf"
                truth_binary = fold_root / f"truth{suffix}"
                archives = [path for _owner, item in archive_items for path in item["paths"]]
                _link_composite(route, archives, truth_binary, fold_root / "link.map")
                query_binary = fold_root / f"query{suffix}"
                result = subprocess.run(
                    [str(_strip_tool(route)), "--strip-debug", str(truth_binary), "-o", str(query_binary)],
                    text=True, capture_output=True, timeout=300, check=False,
                )
                if result.returncode != 0 or not query_binary.is_file():
                    raise RuntimeError(f"query-copy creation failed for {route.id}: {result.stderr[-2000:]}")
                project_parent = run_root / f"worker-{os.getpid()}" / "projects" / f"{position:03d}-{fold}"
                project_dir, program_path = ghidra_fid.analyze_target(
                    query_binary, project_parent, "composite", route.ghidra_language, route.ghidra_compiler_spec
                )
                query_signatures = fold_root / "query-signatures.jsonl"
                signature_summary = ghidra_fid.export_program_signatures(
                    project_dir, "composite", program_path, query_signatures
                )
                matches, examples = _query_index(
                    index,
                    query_signatures,
                    route.id,
                    treatment.id,
                    route.target_os,
                    route.binary_format,
                    mode == "canary",
                )
                threshold = int(evidence["runtime"]["canary" if mode == "canary" else "execution"]["minimum_distinct_hashes"])
                positive = {owner for owner, values in matches.items() if len(values) >= threshold}
                cohort = set(evidence["status"]["randomization"]["canonical_ids"])
                present = set(owners); absent = cohort - present
                failures = []
                for owner in sorted(absent & positive):
                    failures.append({"failure_type": "collision", "library_id": owner, **examples[owner]})
                for owner in sorted(present - positive):
                    failures.append({
                        "failure_type": "miss", "library_id": owner, "function_id": "",
                        "signature": "", "candidate_owner": "", "evidence_path": str(query_signatures.relative_to(root)),
                    })
                fold_results.append({
                    "fold": fold, "binary_format": route.binary_format,
                    "query_sha256": _sha256(query_binary), "truth_sha256": _sha256(truth_binary),
                    "signature_summary": signature_summary,
                    "owner_match_counts": {owner: len(matches.get(owner, set())) for owner in sorted(cohort)},
                    "positive_owners": sorted(positive),
                    "confusion_matrix": {
                        "true_positives": len(present & positive), "false_positives": len(absent & positive),
                        "true_negatives": len(absent - positive), "false_negatives": len(present - positive),
                    },
                    "failures": failures,
                })
                if not execution["retain_ghidra_projects_on_success"]:
                    shutil.rmtree(project_parent, ignore_errors=True)
            document = {
                "schema_version": UNIT_RESULT_SCHEMA, "state": "complete", "mode": mode,
                "position": position, "route_id": route.id, "profile_id": unit["profile_id"],
                "treatment_id": treatment.id, "started_at": _now(),
                "wall_time_ns": time.monotonic_ns() - started_ns, "folds": fold_results,
            }
            _atomic_json(result_path, document)
        except Exception as error:
            _atomic_json(result_path, {
                "schema_version": UNIT_RESULT_SCHEMA, "state": "failed", "mode": mode,
                "position": position, "route_id": route.id, "treatment_id": treatment.id,
                "wall_time_ns": time.monotonic_ns() - started_ns,
                "error": f"{type(error).__name__}: {error}", "folds": fold_results,
            })
            return 1
    return 0


def _aggregate(
    run_root: Path,
    validation_id: str,
    mode: str,
    expected_positions: set[int],
    minimum_hashes: int,
    max_failure_rows: int,
    runtime: Mapping[str, object],
) -> dict[str, object]:
    results = []
    for path in sorted((run_root / "units").glob("*/result.json")):
        row = json.loads(path.read_text(encoding="utf-8"))
        if row.get("mode") == mode and int(row.get("position", -1)) in expected_positions:
            results.append(row)
    failed = [row for row in results if row.get("state") == "failed"]
    matrix = {"true_positives": 0, "false_positives": 0, "true_negatives": 0, "false_negatives": 0}
    failures = []
    wall_time_ns = 0
    for row in results:
        wall_time_ns += int(row.get("wall_time_ns", 0))
        for fold in row.get("folds", []):
            for key in matrix:
                matrix[key] += int(fold["confusion_matrix"][key])
            for failure in fold.get("failures", []):
                failures.append({
                    **failure, "route_id": str(row["route_id"]),
                    "compiler_id": str(row["route_id"]), "treatment_id": str(row["treatment_id"]),
                })
    complete_positions = {int(row["position"]) for row in results if row.get("state") == "complete"}
    complete = not failed and complete_positions == expected_positions
    report = {
        "schema_version": "fidb-machine-validation-canary/v1" if mode == "canary" else "fidb-machine-validation-report/v1",
        "validation_id": validation_id, "state": "measured-complete" if complete else "failed",
        "mode": mode, "finished_at": _now(),
        "runtime_authority": runtime["authority_path"],
        "runtime_authority_sha256": runtime["authority_sha256"],
        "reference_index_schema": REFERENCE_INDEX_SCHEMA,
        "query_copy_policy": QUERY_COPY_POLICY,
        "confusion_matrix": {"unit": "owner-labelled-candidate-decision", **matrix},
        "failure_summary": {
            "collisions": sum(row["failure_type"] == "collision" for row in failures),
            "misses": sum(row["failure_type"] == "miss" for row in failures),
        },
        "failures": failures[:max_failure_rows],
        "metrics": {
            "expected_work_units": len(expected_positions), "complete_work_units": len(complete_positions),
            "failed_work_units": len(failed), "worker_sum_wall_time_ns": wall_time_ns,
            "minimum_distinct_hashes": minimum_hashes,
            "failure_rows_truncated": max(0, len(failures) - max_failure_rows),
        },
    }
    return report


def canary_gate_status(
    project_root: str | Path,
    runtime_path: str | Path = DEFAULT_RUNTIME,
) -> dict[str, object]:
    """Return the latest canary compatible with the current runtime contract."""

    root = Path(project_root).resolve()
    runtime = load_runtime(root, runtime_path)
    output_root = _inside(root, str(runtime["output_root"]), "validation output")
    reports = sorted(
        output_root.glob("*-canary/canary-report.json"),
        key=lambda path: path.stat().st_mtime_ns,
        reverse=True,
    )
    latest = None
    for path in reports:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if latest is None:
            latest = {
                "run_id": path.parent.name,
                "report_path": str(path.relative_to(root)),
                "state": document.get("state", "invalid"),
            }
        if (
            document.get("state") == "measured-complete"
            and document.get("runtime_authority_sha256")
            == runtime["authority_sha256"]
            and document.get("reference_index_schema") == REFERENCE_INDEX_SCHEMA
            and document.get("query_copy_policy") == QUERY_COPY_POLICY
        ):
            return {
                "ready": True,
                "state": "passed",
                "run_id": path.parent.name,
                "report_path": str(path.relative_to(root)),
                "runtime_authority_sha256": runtime["authority_sha256"],
            }
    return {
        "ready": False,
        "state": "not-run" if latest is None else "stale-or-failed",
        "run_id": None if latest is None else latest["run_id"],
        "report_path": None if latest is None else latest["report_path"],
        "runtime_authority_sha256": runtime["authority_sha256"],
    }


def run_validation(project_root: str | Path, mode: str, runtime_path: str | Path = DEFAULT_RUNTIME, run_id: str | None = None) -> dict[str, object]:
    if mode not in {"canary", "full"}:
        raise ValueError("machine-validation mode must be canary or full")
    root = Path(project_root).resolve()
    evidence = resolve_evidence(root, runtime_path)
    if evidence["blockers"]:
        raise ValueError("; ".join(evidence["blockers"]))
    runtime = evidence["runtime"]
    output_root = _inside(root, str(runtime["output_root"]), "validation output")
    output_root.mkdir(parents=True, exist_ok=True)
    if run_id is None:
        run_id = f'{datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")}-{mode}'
    run_root = _run_root(root, runtime, run_id)
    run_root.mkdir(parents=True, exist_ok=True)
    current_path = output_root / "current.json"
    lock = output_root / ".runner.lock"
    descriptor = None
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.write(descriptor, f"{os.getpid()}\n".encode())
    except FileExistsError as error:
        raise ValueError("another machine-validation run is already active") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    positions = (
        {int(value) for value in runtime["canary"]["positions"]}
        if mode == "canary" else {int(unit["position"]) for unit in evidence["manifest"]["work_unit"]}
    )
    status_path = run_root / "status.json"
    prior_status = {}
    if status_path.is_file():
        try:
            prior_status = json.loads(status_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            prior_status = {}
    started = str(prior_status.get("started_at") or _now())
    attempt_started = _now()
    resume_count = int(prior_status.get("resume_count", 0))
    complete_count, failed_count = _result_counts(run_root, mode)
    pause_request = run_root / PAUSE_REQUEST_NAME
    _atomic_json(current_path, {"run_id": run_id, "path": str(status_path.relative_to(root))})
    _atomic_json(status_path, {
        "schema_version": RUN_STATUS_SCHEMA, "validation_id": runtime["validation_id"],
        "run_id": run_id, "mode": mode, "state": "preparing-index", "pid": os.getpid(),
        "started_at": started, "attempt_started_at": attempt_started,
        "resume_count": resume_count, "finished_at": None,
        "expected_work_units": len(positions),
        "complete_work_units": complete_count, "failed_work_units": failed_count,
    })
    try:
        index = build_reference_index(root, evidence, output_root)
        if mode == "full":
            gate = canary_gate_status(root, runtime_path)
            if not gate["ready"]:
                raise ValueError(
                    "full machine validation requires a completed canary for the "
                    "current runtime and reference-index contract"
                )
        pending = sorted(positions)
        worker_count = min(int(runtime["execution"]["workers"]), len(pending))
        shards = [pending[index::worker_count] for index in range(worker_count)]
        processes = []
        for index, shard in enumerate(shards, start=1):
            log_path = run_root / f"worker-{index:02d}.log"
            with log_path.open("ab", buffering=0) as log:
                process = subprocess.Popen(
                    [sys.executable, "-m", "fidb_poc.cli", "machine-validation", "_worker",
                     "--project-root", str(root), "--runtime", str(runtime_path),
                     "--run-id", run_id, "--mode", mode,
                     "--positions", ",".join(map(str, shard))],
                    cwd=root, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                    start_new_session=True, close_fds=True,
                )
            processes.append(process)
        pause_requested = False
        while any(process.poll() is None for process in processes):
            documents = _result_documents(run_root, mode)
            if pause_request.is_file():
                pause_requested = True
                _atomic_json(status_path, {
                    "schema_version": RUN_STATUS_SCHEMA, "validation_id": runtime["validation_id"],
                    "run_id": run_id, "mode": mode, "state": "pausing", "pid": os.getpid(),
                    "worker_pids": [process.pid for process in processes], "started_at": started,
                    "attempt_started_at": attempt_started, "resume_count": resume_count,
                    "finished_at": None, "expected_work_units": len(positions),
                    "complete_work_units": sum(row.get("state") == "complete" for row in documents),
                    "failed_work_units": sum(row.get("state") == "failed" for row in documents),
                })
                _terminate_worker_groups(processes)
                break
            _atomic_json(status_path, {
                "schema_version": RUN_STATUS_SCHEMA, "validation_id": runtime["validation_id"],
                "run_id": run_id, "mode": mode, "state": "running", "pid": os.getpid(),
                "worker_pids": [process.pid for process in processes], "started_at": started,
                "attempt_started_at": attempt_started, "resume_count": resume_count,
                "finished_at": None, "expected_work_units": len(positions),
                "complete_work_units": sum(row.get("state") == "complete" for row in documents),
                "failed_work_units": sum(row.get("state") == "failed" for row in documents),
            })
            time.sleep(5)
        if pause_requested:
            complete_count, failed_count = _result_counts(run_root, mode)
            paused = {
                "schema_version": RUN_STATUS_SCHEMA, "validation_id": runtime["validation_id"],
                "run_id": run_id, "mode": mode, "state": "paused", "pid": os.getpid(),
                "worker_pids": [], "started_at": started, "attempt_started_at": attempt_started,
                "resume_count": resume_count, "finished_at": None, "paused_at": _now(),
                "expected_work_units": len(positions), "complete_work_units": complete_count,
                "failed_work_units": failed_count,
            }
            _atomic_json(status_path, paused)
            return paused
        minimum = int(runtime["canary" if mode == "canary" else "execution"]["minimum_distinct_hashes"])
        report = _aggregate(
            run_root,
            str(runtime["validation_id"]),
            mode,
            positions,
            minimum,
            int(runtime["execution"]["max_failure_rows"]),
            runtime,
        )
        report_path = run_root / ("canary-report.json" if mode == "canary" else "report.json")
        _atomic_json(report_path, report)
        _atomic_json(status_path, {
            "schema_version": RUN_STATUS_SCHEMA, "validation_id": runtime["validation_id"],
            "run_id": run_id, "mode": mode, "state": "complete" if report["state"] == "measured-complete" else "failed",
            "pid": os.getpid(), "worker_pids": [process.pid for process in processes],
            "started_at": started, "finished_at": _now(), "expected_work_units": len(positions),
            "attempt_started_at": attempt_started, "resume_count": resume_count,
            "complete_work_units": report["metrics"]["complete_work_units"],
            "failed_work_units": report["metrics"]["failed_work_units"],
            "report_path": str(report_path.relative_to(root)),
        })
        return report
    except Exception as error:
        _atomic_json(status_path, {
            "schema_version": RUN_STATUS_SCHEMA, "validation_id": runtime["validation_id"],
            "run_id": run_id, "mode": mode, "state": "failed", "pid": os.getpid(),
            "started_at": started, "finished_at": _now(), "expected_work_units": len(positions),
            "attempt_started_at": attempt_started, "resume_count": resume_count,
            "complete_work_units": _result_counts(run_root, mode)[0],
            "failed_work_units": max(1, _result_counts(run_root, mode)[1]),
            "error": f"{type(error).__name__}: {error}",
        })
        raise
    finally:
        lock.unlink(missing_ok=True)


def runtime_status(project_root: str | Path, runtime_path: str | Path = DEFAULT_RUNTIME) -> dict[str, object]:
    root = Path(project_root).resolve()
    runtime = load_runtime(root, runtime_path)
    current = _inside(root, str(runtime["output_root"]), "validation output") / "current.json"
    if not current.is_file():
        return {"state": "not-started", "run_id": None, "mode": None, "complete_work_units": 0, "failed_work_units": 0}
    pointer = json.loads(current.read_text(encoding="utf-8"))
    status_path = _inside(root, str(pointer["path"]), "validation run status")
    if not status_path.is_file():
        return {"state": "invalid", "run_id": pointer.get("run_id"), "mode": None, "complete_work_units": 0, "failed_work_units": 0}
    status = json.loads(status_path.read_text(encoding="utf-8"))
    if status.get("state") in {"queued", "preparing-index", "running", "pausing"}:
        run_id = str(status.get("run_id") or "")
        if not _validation_process_active(status.get("pid"), run_id):
            status = {**status, "state": "interrupted", "worker_pids": []}
    return status


def _current_status_path(root: Path, runtime: Mapping[str, object]) -> Path:
    current = _inside(root, str(runtime["output_root"]), "validation output") / "current.json"
    if not current.is_file():
        raise ValueError("machine validation has no current run")
    pointer = json.loads(current.read_text(encoding="utf-8"))
    status_path = _inside(root, str(pointer["path"]), "validation run status")
    if not status_path.is_file():
        raise ValueError("machine validation current status is missing")
    return status_path


def _clear_stale_lock(output_root: Path, run_id: str) -> None:
    lock = output_root / ".runner.lock"
    if not lock.is_file():
        return
    try:
        pid = int(lock.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        pid = 0
    if _validation_process_active(pid, run_id):
        raise ValueError("machine-validation run process is still active")
    lock.unlink(missing_ok=True)


def _spawn_validation(
    root: Path,
    runtime_path: str | Path,
    mode: str,
    run_id: str,
    log_path: Path,
) -> subprocess.Popen[bytes]:
    with log_path.open("ab", buffering=0) as log:
        return subprocess.Popen(
            [sys.executable, "-m", "fidb_poc.cli", "machine-validation", "run",
             "--project-root", str(root), "--runtime", str(runtime_path),
             "--mode", mode, "--run-id", run_id],
            cwd=root, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True, close_fds=True,
        )


def pause_validation(
    project_root: str | Path,
    runtime_path: str | Path = DEFAULT_RUNTIME,
    *,
    actor: str = "operator",
) -> dict[str, object]:
    root = Path(project_root).resolve()
    runtime = load_runtime(root, runtime_path)
    status_path = _current_status_path(root, runtime)
    status = runtime_status(root, runtime_path)
    if status.get("state") == "paused":
        return status
    if status.get("state") == "interrupted" or (
        status.get("state") == "failed"
        and int(status.get("complete_work_units", 0))
        < int(status.get("expected_work_units", 0))
        and not _validation_process_active(status.get("pid"), str(status.get("run_id") or ""))
    ):
        paused = {
            **status, "state": "paused", "paused_at": _now(),
            "pause_actor": actor, "worker_pids": [],
        }
        _atomic_json(status_path, paused)
        return paused
    if status.get("state") not in {"queued", "preparing-index", "running", "pausing"}:
        raise ValueError("machine validation is not active")
    run_id = str(status["run_id"])
    requested_at = _now()
    _atomic_json(
        status_path.parent / PAUSE_REQUEST_NAME,
        {
            "schema_version": "fidb-machine-validation-pause-request/v1",
            "run_id": run_id,
            "requested_at": requested_at,
            "actor": actor,
        },
    )
    pausing = {
        **status, "state": "pausing", "pause_requested_at": requested_at,
        "pause_actor": actor,
    }
    _atomic_json(status_path, pausing)
    return pausing


def resume_validation(
    project_root: str | Path,
    runtime_path: str | Path = DEFAULT_RUNTIME,
) -> dict[str, object]:
    root = Path(project_root).resolve()
    runtime = load_runtime(root, runtime_path)
    status_path = _current_status_path(root, runtime)
    status = runtime_status(root, runtime_path)
    if status.get("state") not in {"paused", "interrupted", "failed"}:
        raise ValueError("machine validation is not resumable")
    run_id = str(status.get("run_id") or "")
    mode = str(status.get("mode") or "")
    if mode not in {"canary", "full"} or not run_id:
        raise ValueError("machine validation resume identity is invalid")
    if int(status.get("complete_work_units", 0)) >= int(status.get("expected_work_units", 0)):
        raise ValueError("machine validation has no incomplete work to resume")
    if _validation_process_active(status.get("pid"), run_id):
        raise ValueError("machine-validation run process is still active")
    pre = preflight(root, runtime_path)
    if pre["state"] != "ready":
        raise ValueError("; ".join(pre["blockers"]))
    if mode == "full" and not canary_gate_status(root, runtime_path)["ready"]:
        raise ValueError(
            "full machine validation requires a completed canary for the current "
            "runtime and reference-index contract"
        )
    output_root = _inside(root, str(runtime["output_root"]), "validation output")
    _clear_stale_lock(output_root, run_id)
    (status_path.parent / PAUSE_REQUEST_NAME).unlink(missing_ok=True)
    resume_count = int(status.get("resume_count", 0)) + 1
    queued = {
        **status, "state": "queued", "pid": None, "worker_pids": [],
        "finished_at": None, "resumed_at": _now(), "resume_count": resume_count,
    }
    queued.pop("error", None)
    queued.pop("report_path", None)
    _atomic_json(status_path, queued)
    log_path = status_path.parent / "run.log"
    process = _spawn_validation(root, runtime_path, mode, run_id, log_path)
    queued["pid"] = process.pid
    _atomic_json(status_path, queued)
    return {
        "state": "queued", "run_id": run_id, "mode": mode, "pid": process.pid,
        "resume_count": resume_count,
        "complete_work_units": int(status.get("complete_work_units", 0)),
        "failed_work_units": int(status.get("failed_work_units", 0)),
        "log_path": str(log_path.relative_to(root)),
    }


def start_validation(project_root: str | Path, mode: str, runtime_path: str | Path = DEFAULT_RUNTIME) -> dict[str, object]:
    if mode not in {"canary", "full"}:
        raise ValueError("machine-validation mode must be canary or full")
    root = Path(project_root).resolve()
    pre = preflight(root, runtime_path)
    if pre["state"] != "ready":
        raise ValueError("; ".join(pre["blockers"]))
    current = runtime_status(root, runtime_path)
    if current.get("state") in {"preparing-index", "running", "queued", "pausing"}:
        raise ValueError("machine validation is already running")
    if current.get("state") in {"paused", "interrupted"}:
        raise ValueError("resume or explicitly retire the checkpointed machine-validation run")
    if mode == "full" and not canary_gate_status(root, runtime_path)["ready"]:
        raise ValueError(
            "full machine validation requires a completed canary for the current "
            "runtime and reference-index contract"
        )
    run_id = f'{datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")}-{mode}'
    runtime = load_runtime(root, runtime_path)
    run_root = _run_root(root, runtime, run_id)
    run_root.mkdir(parents=True, exist_ok=True)
    log_path = run_root / "run.log"
    status_path = run_root / "status.json"
    output_root = _inside(root, str(runtime["output_root"]), "validation output")
    output_root.mkdir(parents=True, exist_ok=True)
    _atomic_json(
        status_path,
        {
            "schema_version": RUN_STATUS_SCHEMA,
            "validation_id": runtime["validation_id"],
            "run_id": run_id,
            "mode": mode,
            "state": "queued",
            "pid": None,
            "started_at": _now(),
            "finished_at": None,
            "expected_work_units": 0,
            "complete_work_units": 0,
            "failed_work_units": 0,
            "resume_count": 0,
        },
    )
    _atomic_json(
        output_root / "current.json",
        {"run_id": run_id, "path": str(status_path.relative_to(root))},
    )
    process = _spawn_validation(root, runtime_path, mode, run_id, log_path)
    queued = json.loads(status_path.read_text(encoding="utf-8"))
    queued["pid"] = process.pid
    _atomic_json(status_path, queued)
    return {"state": "queued", "run_id": run_id, "mode": mode, "pid": process.pid, "log_path": str(log_path.relative_to(root))}
