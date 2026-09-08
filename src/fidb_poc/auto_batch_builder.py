"""Build small, duration-aware, disarmed queue chunks from reviewed width.

The builder never touches coordinator state.  Its smallest scheduling unit is
one library, one route, and every treatment for that route.  This keeps the
treatment comparison scientifically coherent while allowing one large library
to be spread across several independently admissible chunks.
"""

from __future__ import annotations

from collections import OrderedDict
import hashlib
import json
import math
from pathlib import Path
import tempfile
import tomllib

from .batch_materializer import (
    _ordered_width_axes,
    _queue_identity,
    _resolve_rendered_plan,
)
from .batch_time_model import DEFAULT_MODEL_PATH, compile_time_block_plan
from .batch_time_model import _reviewed_recipe_projections
from .plan_request import queue_identity_digest
from .qualification_pipeline import require_qualification_gates
from .width_batch import load_width_batch
from .width_batch import project_width_batch_readiness

AUTO_BATCH_SCHEMA = "fidb-auto-batch-campaign/v1"
AUTO_BATCH_BUILDER_VERSION = "route-treatment-bundles-v1"
DEFAULT_AUTO_OUTPUT_ROOT = Path("plans/auto-materialized")
DEFAULT_QUEUE_PATH = Path("plans/c-top10-nonapple-width-v2-queue-policy.toml")
DEFAULT_TARGET_MINUTES = 60
DEFAULT_MAX_MINUTES = 85
MANIFEST_NAME = "manifest.toml"
QUEUE_NAME = "queue.toml"
CANARY_QUEUE_NAME = "canary-queue.toml"


def _toml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("TOML number must be finite")
        return json.dumps(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    raise ValueError(f"cannot render TOML value: {type(value).__name__}")


def _relative_project_path(root: Path, value: str | Path, context: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{context} must stay inside project root")
    resolved = (root / path).resolve()
    try:
        return resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(f"{context} must stay inside project root") from error


def _route_bundles(root: Path, time_plan: dict[str, object]) -> list[dict[str, object]]:
    items = sorted(
        (
            item
            for block in time_plan["blocks"]  # type: ignore[index]
            for item in block["items"]
        ),
        key=lambda item: (int(item["rank"]), str(item["source_id"])),
    )
    axes: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {}
    batches: dict[str, dict[str, object]] = {}
    bundles = []
    for item in items:
        authority = str(item["batch_authority"])
        if authority not in batches:
            batches[authority] = project_width_batch_readiness(
                load_width_batch(root, root / authority),
                _reviewed_recipe_projections(root),
            )
            axes[authority] = _ordered_width_axes(root, batches[authority])
        routes, treatments = axes[authority]
        library_matches = [
            row
            for row in batches[authority]["libraries"]  # type: ignore[index]
            if row["id"] == item["source_id"] and row["version"] == item["version"]
        ]
        if len(library_matches) != 1:
            raise ValueError(
                f"time model source {item['source_id']}@{item['version']} no longer "
                f"matches {authority}"
            )
        recipe_id = str(library_matches[0]["recipe_id"])
        applicable_routes = set(map(str, library_matches[0]["applicable_route_ids"]))
        selected_routes = tuple(route for route in routes if route in applicable_routes)
        expected = len(selected_routes) * len(treatments)
        if int(item["executions"]) != expected:
            raise ValueError(
                f"{item['source_id']} cannot be split into native route bundles: "
                f"{item['executions']} executions != {expected}"
            )
        route_hours = float(item["estimated_hours"]) / len(selected_routes)
        for route in selected_routes:
            bundles.append(
                {
                    "rank": int(item["rank"]),
                    "source_id": str(item["source_id"]),
                    "label": str(item["label"]),
                    "version": str(item["version"]),
                    "recipe_id": recipe_id,
                    "batch_authority": authority,
                    "route_id": route,
                    "treatment_ids": list(treatments),
                    "executions": len(treatments),
                    "estimated_hours": route_hours,
                }
            )
    return bundles


def _pack_route_bundles(
    bundles: list[dict[str, object]],
    *,
    target_hours: float,
    max_hours: float,
) -> list[list[dict[str, object]]]:
    """Sequentially pack stable route bundles within a hard central estimate."""

    chunks: list[list[dict[str, object]]] = []
    current: list[dict[str, object]] = []
    total = 0.0
    for bundle in bundles:
        hours = float(bundle["estimated_hours"])
        if hours > max_hours + 1e-12:
            raise ValueError(
                f"indivisible route bundle {bundle['source_id']}/{bundle['route_id']} "
                f"exceeds the maximum chunk duration"
            )
        if current and total + hours > max_hours + 1e-12:
            chunks.append(current)
            current = []
            total = 0.0
        current.append(bundle)
        total += hours
        if total >= target_hours - 1e-12:
            chunks.append(current)
            current = []
            total = 0.0
    if current:
        chunks.append(current)
    return chunks


def _matrix_groups(
    bundles: list[dict[str, object]],
) -> list[dict[str, object]]:
    grouped: OrderedDict[tuple[str, str, tuple[str, ...]], dict[str, object]] = (
        OrderedDict()
    )
    for bundle in bundles:
        key = (
            str(bundle["batch_authority"]),
            str(bundle["recipe_id"]),
            tuple(str(value) for value in bundle["treatment_ids"]),
        )
        group = grouped.setdefault(
            key,
            {
                "batch_authority": key[0],
                "recipe_id": key[1],
                "treatment_ids": list(key[2]),
                "route_ids": [],
            },
        )
        group["route_ids"].append(str(bundle["route_id"]))  # type: ignore[index]
    return list(grouped.values())


def _append_qualification_gates(
    lines: list[str], qualification_gates: list[dict[str, object]]
) -> None:
    for gate in qualification_gates:
        lines.extend(
            [
                "",
                "[[qualification_gate]]",
                f"batch_id = {_toml_value(gate['batch_id'])}",
                f"batch_digest = {_toml_value(gate['batch_digest'])}",
                f"authority_path = {_toml_value(gate['authority_path'])}",
                f"authority_sha256 = {_toml_value(gate['authority_sha256'])}",
                f"pipeline_authority_path = {_toml_value(gate['pipeline_authority_path'])}",
                f"pipeline_authority_sha256 = {_toml_value(gate['pipeline_authority_sha256'])}",
                f"input_digest = {_toml_value(gate['input_digest'])}",
                f"qualification_digest = {_toml_value(gate['qualification_digest'])}",
                f"evidence_path = {_toml_value(gate['evidence_path'])}",
                f"evidence_sha256 = {_toml_value(gate['evidence_sha256'])}",
            ]
        )


def _render_plan(
    chunk: dict[str, object],
    qualification_gates: list[dict[str, object]] | None = None,
) -> str:
    groups = chunk["groups"]
    recipe_order = list(
        dict.fromkeys(str(group["recipe_id"]) for group in groups)  # type: ignore[union-attr]
    )
    lines = [
        '# Generated by "fidb-poc auto-batches". Do not hand edit.',
        'schema_version = "fidb-plan/v1"',
        f"name = {_toml_value(chunk['id'])}",
        "",
        "[policy]",
        f"max_cells = {int(chunk['executions'])}",
        'priority = "normal"',
        "",
        "[coverage]",
        "factor_variants = []",
        "",
        "[queue]",
        'strategy = "recipe-then-variant"',
        f"recipe_order = {_toml_value(recipe_order)}",
    ]
    _append_qualification_gates(lines, qualification_gates or [])
    for index, group in enumerate(groups, start=1):  # type: ignore[arg-type]
        lines.extend(
            [
                "",
                "[[matrix]]",
                f"id = {_toml_value(str(chunk['id']) + f'-width-{index:02d}')}",
                'kind = "width-native"',
                f"width_batch = {_toml_value(group['batch_authority'])}",
                f"recipes = {_toml_value([group['recipe_id']])}",
                f"routes = {_toml_value(group['route_ids'])}",
                f"treatments = {_toml_value(group['treatment_ids'])}",
            ]
        )
    return "\n".join(lines) + "\n"


def _render_validation_plan(
    campaign_id: str,
    chunks: list[dict[str, object]],
    qualification_gates: list[dict[str, object]] | None = None,
) -> str:
    """Render every final matrix once so authority resolution is shared."""

    executions = sum(int(chunk["executions"]) for chunk in chunks)
    recipe_order = list(
        dict.fromkeys(
            str(group["recipe_id"])
            for chunk in chunks
            for group in chunk["groups"]  # type: ignore[union-attr]
        )
    )
    lines = [
        '# Ephemeral aggregate validation for "fidb-poc auto-batches".',
        'schema_version = "fidb-plan/v1"',
        f"name = {_toml_value(campaign_id + '-validation')}",
        "",
        "[policy]",
        f"max_cells = {executions}",
        'priority = "normal"',
        "",
        "[coverage]",
        "factor_variants = []",
        "",
        "[queue]",
        'strategy = "recipe-then-variant"',
        f"recipe_order = {_toml_value(recipe_order)}",
    ]
    _append_qualification_gates(lines, qualification_gates or [])
    for chunk in chunks:
        for index, group in enumerate(chunk["groups"], start=1):  # type: ignore[arg-type]
            lines.extend(
                [
                    "",
                    "[[matrix]]",
                    f"id = {_toml_value(str(chunk['id']) + f'-width-{index:02d}')}",
                    'kind = "width-native"',
                    f"width_batch = {_toml_value(group['batch_authority'])}",
                    f"recipes = {_toml_value([group['recipe_id']])}",
                    f"routes = {_toml_value(group['route_ids'])}",
                    f"treatments = {_toml_value(group['treatment_ids'])}",
                ]
            )
    return "\n".join(lines) + "\n"


def _render_queue(
    document: dict[str, object],
    source_queue: dict[str, object],
    *,
    canary_only: bool = False,
) -> str:
    source_settings = source_queue["queue"]
    source_schedule = source_queue.get("schedule", {})
    source_resources = source_queue.get("resources", {})
    source_notifications = source_queue.get("notifications", {})
    profile = document["performance_profile"]
    settings = profile["settings"]  # type: ignore[index]
    workers = settings["workers"]
    if not isinstance(workers, int) or isinstance(workers, bool):
        raise ValueError("auto batches require an exactly resolved worker count")
    chunks = (
        document["chunks"][:1] if canary_only else document["chunks"]  # type: ignore[index]
    )
    batch_order = [str(chunk["id"]) for chunk in chunks]
    lines = [
        '# Generated by "fidb-poc auto-batches"; reviewed and disarmed.',
        "# Manual start admits one chunk. The schedule chains drained chunks",
        "# while its claim window remains open and never interrupts a started chunk.",
        'schema_version = "fidb-queue/v1"',
        f"name = {_toml_value(str(document['id']) + ('-canary-queue' if canary_only else '-queue'))}",
        "",
        "[queue]",
        "armed = false",
        f"performance_profile = {_toml_value(profile['id'])}",  # type: ignore[index]
        f"max_workers = {workers}",
        f"batch_order = {_toml_value(batch_order)}",
    ]
    for name in (
        "poll_seconds",
        "lease_seconds",
        "max_attempts",
        "retry_backoff_seconds",
        "retry_backoff_max_seconds",
        "authority_failure_threshold",
    ):
        if name in source_settings:  # type: ignore[operator]
            lines.append(f"{name} = {_toml_value(source_settings[name])}")  # type: ignore[index]

    lines.extend(["", "[schedule]"])
    schedule = dict(source_schedule)  # type: ignore[arg-type]
    schedule["enabled"] = False if canary_only else schedule.get("enabled", False)
    schedule["chain_batches"] = not canary_only
    schedule["finish_started_batch"] = True
    schedule.pop("hard_cutoff", None)
    for name in (
        "enabled",
        "timezone",
        "days",
        "start",
        "stop_claiming",
        "finish_started_batch",
        "chain_batches",
    ):
        if name in schedule:
            lines.append(f"{name} = {_toml_value(schedule[name])}")

    for table_name, table in (
        ("resources", source_resources),
        ("notifications", source_notifications),
    ):
        lines.extend(["", f"[{table_name}]"])
        for name, value in table.items():  # type: ignore[union-attr]
            lines.append(f"{name} = {_toml_value(value)}")

    for chunk in chunks:
        lines.extend(
            [
                "",
                "[[batch]]",
                f"id = {_toml_value(chunk['id'])}",
                f"name = {_toml_value(chunk['name'])}",
                f"plan = {_toml_value(chunk['plan'])}",
                f"plan_sha256 = {_toml_value(chunk['plan_sha256'])}",
                f"queue_digest = {_toml_value(chunk['queue_digest'])}",
                f"executions = {int(chunk['executions'])}",
            ]
        )
    return "\n".join(lines) + "\n"


def _render_manifest(document: dict[str, object]) -> str:
    summary = document["summary"]
    policy = document["policy"]
    lines = [
        '# Generated by "fidb-poc auto-batches". Do not hand edit.',
        f"schema_version = {_toml_value(document['schema_version'])}",
        f"builder_version = {_toml_value(document['builder_version'])}",
        f"id = {_toml_value(document['id'])}",
        'state = "generated-disarmed"',
        f"time_model = {_toml_value(document['time_model'])}",
        f"time_plan_digest = {_toml_value(document['time_plan_digest'])}",
        f"source_queue_sha256 = {_toml_value(document['source_queue_sha256'])}",
        f"performance_profile = {_toml_value(document['performance_profile']['id'])}",  # type: ignore[index]
        f"queue = {_toml_value(document['queue_path'])}",
        f"canary_queue = {_toml_value(document['canary_queue_path'])}",
        f"campaign_digest = {_toml_value(document['campaign_digest'])}",
        "",
        "[policy]",
    ]
    for name, value in policy.items():  # type: ignore[union-attr]
        lines.append(f"{name} = {_toml_value(value)}")
    lines.extend(["", "[summary]"])
    for name, value in summary.items():  # type: ignore[union-attr]
        lines.append(f"{name} = {_toml_value(value)}")
    for gate in document.get("qualification_gates", []):
        lines.extend(
            [
                "",
                "[[qualification_gates]]",
                f"batch_id = {_toml_value(gate['batch_id'])}",
                f"batch_digest = {_toml_value(gate['batch_digest'])}",
                f"authority_path = {_toml_value(gate['authority_path'])}",
                f"authority_sha256 = {_toml_value(gate['authority_sha256'])}",
                f"pipeline_authority_path = {_toml_value(gate['pipeline_authority_path'])}",
                f"pipeline_authority_sha256 = {_toml_value(gate['pipeline_authority_sha256'])}",
                f"input_digest = {_toml_value(gate['input_digest'])}",
                f"qualification_digest = {_toml_value(gate['qualification_digest'])}",
                f"evidence_path = {_toml_value(gate['evidence_path'])}",
                f"evidence_sha256 = {_toml_value(gate['evidence_sha256'])}",
            ]
        )
    for chunk in document["chunks"]:  # type: ignore[index]
        lines.extend(
            [
                "",
                "[[chunks]]",
                f"id = {_toml_value(chunk['id'])}",
                f"position = {int(chunk['position'])}",
                f"name = {_toml_value(chunk['name'])}",
                f"plan = {_toml_value(chunk['plan'])}",
                f"plan_sha256 = {_toml_value(chunk['plan_sha256'])}",
                f"queue_digest = {_toml_value(chunk['queue_digest'])}",
                f"executions = {int(chunk['executions'])}",
                f"estimated_minutes = {_toml_value(chunk['estimated_minutes'])}",
                f"planning_lower_minutes = {_toml_value(chunk['planning_lower_minutes'])}",
                f"planning_upper_minutes = {_toml_value(chunk['planning_upper_minutes'])}",
                f"source_ids = {_toml_value(chunk['source_ids'])}",
                f"route_ids = {_toml_value(chunk['route_ids'])}",
            ]
        )
    return "\n".join(lines) + "\n"


def compile_auto_batches(
    project_root: str | Path,
    model_path: str | Path = DEFAULT_MODEL_PATH,
    output_root: str | Path = DEFAULT_AUTO_OUTPUT_ROOT,
    *,
    queue_path: str | Path = DEFAULT_QUEUE_PATH,
    target_minutes: int = DEFAULT_TARGET_MINUTES,
    max_minutes: int = DEFAULT_MAX_MINUTES,
    performance_profile: str | None = None,
) -> dict[str, object]:
    """Compile duration-aware plans and a disarmed queue without writing."""

    if target_minutes < 1 or max_minutes < 1 or target_minutes > max_minutes:
        raise ValueError("target/max minutes must be positive and target <= maximum")
    root = Path(project_root).expanduser().resolve()
    output_relative = _relative_project_path(root, output_root, "output root")
    queue_relative = _relative_project_path(root, queue_path, "source queue")
    source_queue_path = root / queue_relative
    if not source_queue_path.is_file():
        raise ValueError("source queue is not a project file")
    source_queue = tomllib.loads(source_queue_path.read_text(encoding="utf-8"))
    time_plan = compile_time_block_plan(
        root, model_path, performance_profile=performance_profile
    )
    bundles = _route_bundles(root, time_plan)
    batch_authorities = list(
        dict.fromkeys(str(bundle["batch_authority"]) for bundle in bundles)
    )
    batches = {
        authority: load_width_batch(root, root / authority)
        for authority in batch_authorities
    }
    qualification_gates = require_qualification_gates(root, list(batches.values()))
    qualification_by_batch = {
        str(gate["batch_id"]): gate for gate in qualification_gates
    }
    qualification_by_authority = {
        authority: qualification_by_batch.get(str(batch["id"]))
        for authority, batch in batches.items()
    }
    packed = _pack_route_bundles(
        bundles,
        target_hours=target_minutes / 60,
        max_hours=max_minutes / 60,
    )
    campaign_id = f"{time_plan['id']}-auto-{target_minutes}m-{max_minutes}m"
    directory = output_relative / campaign_id
    uncertainty = float(time_plan["policy"]["uncertainty_fraction"])  # type: ignore[index]
    chunks: list[dict[str, object]] = []
    rendered: dict[str, str] = {}
    for position, chunk_bundles in enumerate(packed, start=1):
        chunk_id = f"{campaign_id}-chunk-{position:03d}"
        hours = sum(float(row["estimated_hours"]) for row in chunk_bundles)
        executions = sum(int(row["executions"]) for row in chunk_bundles)
        groups = _matrix_groups(chunk_bundles)
        sources = list(dict.fromkeys(str(row["source_id"]) for row in chunk_bundles))
        routes = [str(row["route_id"]) for row in chunk_bundles]
        chunk = {
            "id": chunk_id,
            "position": position,
            "name": " + ".join(sources) + f" · width chunk {position:03d}",
            "executions": executions,
            "estimated_minutes": round(hours * 60, 3),
            "planning_lower_minutes": round(hours * (1 - uncertainty) * 60, 3),
            "planning_upper_minutes": round(hours * (1 + uncertainty) * 60, 3),
            "source_ids": sources,
            "route_ids": routes,
            "groups": groups,
        }
        relative_plan = directory / f"chunk-{position:03d}.toml"
        chunk_gates = [
            qualification_by_authority[authority]
            for authority in dict.fromkeys(
                str(group["batch_authority"]) for group in groups
            )
            if qualification_by_authority[authority] is not None
        ]
        payload = _render_plan(chunk, chunk_gates)
        chunk.update(
            {
                "plan": str(relative_plan),
                "plan_sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            }
        )
        chunks.append(chunk)
        rendered[str(relative_plan)] = payload

    validation_payload = _render_validation_plan(
        campaign_id, chunks, qualification_gates
    )
    resolved = _resolve_rendered_plan(
        root, f"{campaign_id}-validation.toml", validation_payload
    )
    all_identity = _queue_identity(resolved)
    claimed_base_cells: set[str] = set()
    for chunk in chunks:
        prefixes = tuple(
            f"{chunk['id']}-width-{index:02d}:"
            for index, _group in enumerate(chunk["groups"], start=1)  # type: ignore[arg-type]
        )
        selected = [
            row for row in all_identity if str(row["base_cell"]).startswith(prefixes)
        ]
        identity = [
            {**row, "position": position}
            for position, row in enumerate(selected, start=1)
        ]
        if len(identity) != int(chunk["executions"]):
            raise ValueError(
                f"{chunk['id']} resolved {len(identity)} cells; expected "
                f"{chunk['executions']}"
            )
        base_cells = {str(row["base_cell"]) for row in identity}
        if claimed_base_cells & base_cells:
            raise ValueError("auto chunk authority resolution produced duplicate cells")
        claimed_base_cells.update(base_cells)
        chunk["queue_digest"] = queue_identity_digest(identity)

    total_executions = sum(int(chunk["executions"]) for chunk in chunks)
    expected_executions = int(time_plan["summary"]["executions"])  # type: ignore[index]
    if total_executions != expected_executions:
        raise ValueError(
            f"auto chunks cover {total_executions} cells; expected {expected_executions}"
        )
    if len(claimed_base_cells) != len(all_identity):
        raise ValueError("auto chunks did not partition the aggregate resolved queue")
    for chunk in chunks:
        chunk.pop("groups")
    body = {
        "schema_version": AUTO_BATCH_SCHEMA,
        "builder_version": AUTO_BATCH_BUILDER_VERSION,
        "id": campaign_id,
        "state": "generated-disarmed",
        "time_model": time_plan["authority_path"],
        "time_plan_digest": time_plan["plan_digest"],
        "performance_profile": time_plan["performance_profile"],
        "source_queue": str(queue_relative),
        "source_queue_sha256": hashlib.sha256(
            source_queue_path.read_bytes()
        ).hexdigest(),
        "queue_path": str(directory / QUEUE_NAME),
        "canary_queue_path": str(directory / CANARY_QUEUE_NAME),
        "manifest_path": str(directory / MANIFEST_NAME),
        "policy": {
            "target_minutes": target_minutes,
            "max_minutes": max_minutes,
            "uncertainty_fraction": uncertainty,
            "atomic_unit": "one-library-one-route-all-treatments",
            "packing": "stable-sequential-target-with-hard-central-ceiling",
            "scheduled_chaining": True,
            "finish_started_chunk": True,
        },
        "summary": {
            "chunks": len(chunks),
            "libraries": len({row["source_id"] for row in bundles}),
            "route_bundles": len(bundles),
            "executions": total_executions,
            "estimated_hours": time_plan["summary"]["estimated_hours"],  # type: ignore[index]
            "planning_lower_hours": time_plan["summary"]["planning_lower_hours"],  # type: ignore[index]
            "planning_upper_hours": time_plan["summary"]["planning_upper_hours"],  # type: ignore[index]
        },
        "chunks": chunks,
    }
    if qualification_gates:
        body["qualification_gates"] = qualification_gates
    canonical = json.dumps(
        body, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    body["campaign_digest"] = hashlib.sha256(canonical).hexdigest()
    rendered[body["queue_path"]] = _render_queue(body, source_queue)
    rendered[body["canary_queue_path"]] = _render_queue(
        body, source_queue, canary_only=True
    )
    rendered[body["manifest_path"]] = _render_manifest(body)
    return {**body, "rendered_files": rendered}


def write_auto_batches(document: dict[str, object], project_root: str | Path) -> None:
    """Atomically write generated files; never arm or synchronize the queue."""

    root = Path(project_root).expanduser().resolve()
    rendered = document.get("rendered_files")
    if not isinstance(rendered, dict):
        raise ValueError("compiled auto batches contain no rendered files")
    for relative, payload in rendered.items():
        path = root / _relative_project_path(root, relative, "generated output")
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as temporary:
            temporary.write(str(payload))
            temporary_path = Path(temporary.name)
        temporary_path.replace(path)


def check_auto_batches(
    document: dict[str, object], project_root: str | Path
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    mismatches = []
    for relative, payload in document["rendered_files"].items():  # type: ignore[index]
        path = root / _relative_project_path(root, relative, "generated output")
        if not path.is_file():
            mismatches.append({"path": relative, "reason": "missing"})
        elif path.read_text(encoding="utf-8") != payload:
            mismatches.append({"path": relative, "reason": "content-drift"})
    return {
        "state": "current" if not mismatches else "drifted",
        "checked_files": len(document["rendered_files"]),  # type: ignore[arg-type]
        "mismatches": mismatches,
    }
