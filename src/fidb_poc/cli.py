from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

from .config import RecipesNotFoundError, load_configuration, select_configuration
from .pipeline import PipelineError, doctor, execute, plan
from .plan_request import resolve_plan, write_resolved_plan
from .request_queue import record_missing_requests

# Phase 2 CLI unification: fidb-hunt's investigate/hunt/build-malware surface
# lives under this same binary instead of a second entry point (fidb-hunt
# stays as a thin alias -- see hunt_cli.main). "doctor" is renamed
# hunt-doctor here since fidb-poc already has a --doctor flag with a
# different meaning (build-tool validation vs hunt-capability report).
_HUNT_SUBCOMMANDS = {
    "inspect": "inspect",
    "investigate": "investigate",
    "hunt": "hunt",
    "build-malware": "build-malware",
    "hunt-doctor": "doctor",
}


def _performance_main(argv: list[str]) -> int:
    result = argparse.ArgumentParser(
        prog="fidb-poc performance",
        description="Inspect the reviewed performance-profile authority.",
    )
    result.add_argument("profile", nargs="?")
    result.add_argument("--project-root", type=Path, default=Path.cwd())
    result.add_argument(
        "--resolve-auto",
        action="store_true",
        help="detect this host and show the exact effective automatic settings",
    )
    arguments = result.parse_args(argv)
    try:
        from .performance_profiles import load_performance_profiles

        catalog = load_performance_profiles(arguments.project_root)
        document = catalog.document()
        if arguments.profile:
            document = {
                "schema_version": document["schema_version"],
                "authority_path": document["authority_path"],
                "default_profile": document["default_profile"],
                "profile": catalog.select(arguments.profile).document(),
            }
        if arguments.resolve_auto:
            from .host_capacity import (
                detect_host_capacity,
                resolve_automatic_performance,
            )

            document["automatic_resolution"] = resolve_automatic_performance(
                detect_host_capacity(), catalog.automatic_policy
            ).document()
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def _plan_time_blocks_main(argv: list[str]) -> int:
    result = argparse.ArgumentParser(
        prog="fidb-poc plan-time-blocks",
        description="Compile evidence-based, bounded width blocks without queuing work.",
    )
    result.add_argument("--project-root", type=Path, default=Path.cwd())
    result.add_argument(
        "--model", type=Path, default=Path("performance/batch-planning.toml")
    )
    result.add_argument("--performance-profile")
    arguments = result.parse_args(argv)
    try:
        from .batch_time_model import compile_time_block_plan

        document = compile_time_block_plan(
            arguments.project_root,
            arguments.model,
            performance_profile=arguments.performance_profile,
        )
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def _materialize_batches_main(argv: list[str]) -> int:
    result = argparse.ArgumentParser(
        prog="fidb-poc materialize-batches",
        description=(
            "Freeze the reviewed time-block projection into disarmed queue plans."
        ),
    )
    result.add_argument("--project-root", type=Path, default=Path.cwd())
    result.add_argument(
        "--model", type=Path, default=Path("performance/batch-planning.toml")
    )
    result.add_argument("--output-root", type=Path, default=Path("plans/materialized"))
    mode = result.add_mutually_exclusive_group()
    mode.add_argument(
        "--write",
        action="store_true",
        help="atomically write the plans and manifest; never arms the queue",
    )
    mode.add_argument(
        "--check",
        action="store_true",
        help="fail if checked-in materialization differs from current authority",
    )
    arguments = result.parse_args(argv)
    try:
        from .batch_materializer import (
            check_materialization,
            compile_materialization,
            write_materialization,
        )

        document = compile_materialization(
            arguments.project_root, arguments.model, arguments.output_root
        )
        rendered = document.pop("rendered_plans")
        if arguments.write:
            document["rendered_plans"] = rendered
            write_materialization(document, arguments.project_root)
            document.pop("rendered_plans")
            document["check"] = {
                "state": "written-disarmed",
                "checked_files": len(rendered) + 1,
                "mismatches": [],
            }
        elif arguments.check:
            document["rendered_plans"] = rendered
            check = check_materialization(document, arguments.project_root)
            document.pop("rendered_plans")
            document["check"] = check
            print(json.dumps(document, indent=2, sort_keys=True))
            return 0 if check["state"] == "current" else 1
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def _auto_batches_main(argv: list[str]) -> int:
    result = argparse.ArgumentParser(
        prog="fidb-poc auto-batches",
        description=(
            "Build duration-aware route chunks and a chaining, disarmed queue."
        ),
    )
    result.add_argument("--project-root", type=Path, default=Path.cwd())
    result.add_argument(
        "--model", type=Path, default=Path("performance/batch-planning.toml")
    )
    result.add_argument(
        "--source-queue",
        type=Path,
        default=Path("plans/c-top10-nonapple-width-v2-queue-policy.toml"),
    )
    result.add_argument(
        "--output-root", type=Path, default=Path("plans/auto-materialized")
    )
    result.add_argument("--performance-profile")
    result.add_argument("--target-minutes", type=int, default=60)
    result.add_argument("--max-minutes", type=int, default=85)
    mode = result.add_mutually_exclusive_group()
    mode.add_argument(
        "--write",
        action="store_true",
        help="atomically write generated plans and their still-disarmed queue",
    )
    mode.add_argument(
        "--check",
        action="store_true",
        help="fail if generated files differ from current authorities",
    )
    arguments = result.parse_args(argv)
    try:
        from .auto_batch_builder import (
            check_auto_batches,
            compile_auto_batches,
            write_auto_batches,
        )

        document = compile_auto_batches(
            arguments.project_root,
            arguments.model,
            arguments.output_root,
            queue_path=arguments.source_queue,
            target_minutes=arguments.target_minutes,
            max_minutes=arguments.max_minutes,
            performance_profile=arguments.performance_profile,
        )
        rendered = document.pop("rendered_files")
        if arguments.write:
            document["rendered_files"] = rendered
            write_auto_batches(document, arguments.project_root)
            document.pop("rendered_files")
            document["check"] = {
                "state": "written-disarmed",
                "checked_files": len(rendered),
                "mismatches": [],
            }
        elif arguments.check:
            document["rendered_files"] = rendered
            check = check_auto_batches(document, arguments.project_root)
            document.pop("rendered_files")
            document["check"] = check
            print(json.dumps(document, indent=2, sort_keys=True))
            return 0 if check["state"] == "current" else 1
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def _machine_validation_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="fidb-poc machine-validation",
        description=(
            "Inspect or reconcile the fail-closed ten-library validation scheduler."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for command in (
        "status",
        "reconcile",
        "materialize",
        "preflight",
        "start",
        "pause",
        "requeue-failed",
        "resume",
        "run",
        "qualify-links",
        "analyze-hashes",
        "qualify-matcher",
        "run-matcher",
        "scheduled-matcher",
        "freeze-reference-comparison",
        "_matcher-worker",
        "scheduled-hashes",
        "_worker",
    ):
        child = commands.add_parser(command)
        child.add_argument("--project-root", type=Path, default=Path.cwd())
        if command in {"status", "reconcile", "materialize"}:
            child.add_argument(
                "--authority",
                type=Path,
                default=Path("validation/machine-validation.toml"),
            )
        elif command == "scheduled-hashes":
            child.add_argument(
                "--schedule",
                type=Path,
                default=Path("validation/machine-validation-hash-schedule.toml"),
            )
        elif command == "qualify-links":
            child.add_argument(
                "--qualification",
                type=Path,
                default=Path("validation/machine-validation-link-qualification.toml"),
            )
        elif command == "freeze-reference-comparison":
            child.add_argument(
                "--comparison",
                type=Path,
                default=Path("validation/fid-reference-comparison.toml"),
            )
        else:
            child.add_argument(
                "--runtime",
                type=Path,
                default=Path("validation/machine-validation-runtime.toml"),
            )
        if command == "materialize":
            mode = child.add_mutually_exclusive_group()
            mode.add_argument("--write", action="store_true")
            mode.add_argument("--check", action="store_true")
        if command == "qualify-links":
            mode = child.add_mutually_exclusive_group()
            mode.add_argument("--execute", action="store_true")
            mode.add_argument("--status", action="store_true")
        if command in {"start", "run", "_worker"}:
            child.add_argument("--mode", choices=("canary", "full"), required=True)
        if command == "start":
            child.add_argument("--run-id")
        if command == "resume":
            child.add_argument(
                "--foreground",
                action="store_true",
                help="keep the resumed run attached for a service-chain handoff",
            )
        if command in {"run", "analyze-hashes", "qualify-matcher", "_worker"}:
            child.add_argument("--run-id", required=True)
        if command == "analyze-hashes":
            child.add_argument(
                "--qualify-backend",
                action="store_true",
                help="run the explicitly admitted canonical/candidate backend comparison",
            )
        if command == "qualify-matcher":
            child.add_argument("--position", type=int, required=True)
            child.add_argument("--fold", choices=("A", "B"), required=True)
            child.add_argument(
                "--reuse-oracle",
                action="store_true",
                help="replay the retained native-oracle input without starting Ghidra",
            )
            child.add_argument(
                "--matching-authority",
                type=Path,
                default=Path("validation/fid-matching.toml"),
            )
        if command in {"run-matcher", "scheduled-matcher", "_matcher-worker"}:
            child.add_argument(
                "--matcher-campaign",
                type=Path,
                default=Path("validation/fid-matching-run.toml"),
            )
        if command == "run-matcher":
            child.add_argument("--mode", choices=("canary", "full"), required=True)
        if command == "_matcher-worker":
            child.add_argument("--cases", required=True)
            child.add_argument("--mode", choices=("canary", "full"), required=True)
        if command == "_worker":
            child.add_argument("--positions", required=True)
        if command == "requeue-failed":
            child.add_argument("--positions", required=True)
    arguments = parser.parse_args(argv)
    try:
        from .machine_validation import (
            check_validation_batch,
            compile_machine_validation,
            compile_validation_batch,
            reconcile_machine_validation,
            write_validation_batch,
        )
        from .machine_validation_runner import (
            _worker,
            pause_validation,
            preflight,
            requeue_failed_validation,
            resume_validation,
            run_validation,
            runtime_status,
            start_validation,
        )
        from .machine_validation_hashes import analyze_hashes, scheduled_hash_analysis

        if arguments.command == "qualify-links":
            from .machine_validation_links import (
                compile_link_qualification,
                link_qualification_status,
                run_link_qualification,
            )

            if arguments.execute:
                document = run_link_qualification(
                    arguments.project_root, arguments.qualification
                )
                success = document["state"] == "qualified"
            elif arguments.status:
                document = link_qualification_status(
                    arguments.project_root, arguments.qualification
                )
                success = bool(document["satisfied"])
            else:
                document = compile_link_qualification(
                    arguments.project_root, arguments.qualification
                )
                document.pop("_evidence", None)
                success = True
            print(json.dumps(document, indent=2, sort_keys=True))
            return 0 if success else 1
        if arguments.command == "preflight":
            document = preflight(arguments.project_root, arguments.runtime)
            print(json.dumps(document, indent=2, sort_keys=True))
            return 0 if document["state"] == "ready" else 1
        if arguments.command == "start":
            document = start_validation(
                arguments.project_root,
                arguments.mode,
                arguments.runtime,
                arguments.run_id,
            )
            print(json.dumps(document, indent=2, sort_keys=True))
            return 0
        if arguments.command == "pause":
            document = pause_validation(
                arguments.project_root, arguments.runtime, actor="cli"
            )
            print(json.dumps(document, indent=2, sort_keys=True))
            return 0
        if arguments.command == "requeue-failed":
            document = requeue_failed_validation(
                arguments.project_root,
                [int(value) for value in arguments.positions.split(",")],
                arguments.runtime,
                actor="cli",
            )
            print(json.dumps(document, indent=2, sort_keys=True))
            return 0
        if arguments.command == "resume":
            document = resume_validation(
                arguments.project_root,
                arguments.runtime,
                foreground=arguments.foreground,
            )
            print(json.dumps(document, indent=2, sort_keys=True))
            if arguments.foreground:
                return (
                    0
                    if document.get("state") in {"complete", "measured-complete"}
                    else 1
                )
            return 0
        if arguments.command == "run":
            document = run_validation(
                arguments.project_root,
                arguments.mode,
                arguments.runtime,
                arguments.run_id,
            )
            print(json.dumps(document, indent=2, sort_keys=True))
            return 0 if document["state"] == "measured-complete" else 1
        if arguments.command == "analyze-hashes":
            document = analyze_hashes(
                arguments.project_root,
                arguments.run_id,
                runtime_path=arguments.runtime,
                qualify_backend=arguments.qualify_backend,
            )
            print(json.dumps(document, indent=2, sort_keys=True))
            return 0 if document["state"] == "measured-complete" else 1
        if arguments.command == "qualify-matcher":
            from .fid_match_qualification import qualify_retained_validation

            document = qualify_retained_validation(
                arguments.project_root,
                arguments.run_id,
                position=arguments.position,
                fold=arguments.fold,
                runtime_path=arguments.runtime,
                authority_path=arguments.matching_authority,
                reuse_oracle=arguments.reuse_oracle,
            )
            print(json.dumps(document, indent=2, sort_keys=True))
            return 0 if document["state"] == "qualified" else 1
        if arguments.command == "freeze-reference-comparison":
            from .fid_reference_comparison import freeze_reference_comparison

            document = freeze_reference_comparison(
                arguments.project_root, arguments.comparison
            )
            print(json.dumps(document, indent=2, sort_keys=True))
            return 0
        if arguments.command in {"run-matcher", "scheduled-matcher", "_matcher-worker"}:
            from .fid_matching_campaign import (
                run_campaign,
                scheduled_campaign,
                worker_cases,
            )

            if arguments.command == "run-matcher":
                document = run_campaign(
                    arguments.project_root,
                    arguments.mode,
                    arguments.matcher_campaign,
                )
                print(json.dumps(document, indent=2, sort_keys=True))
                return (
                    0 if document["state"] in {"qualified", "measured-complete"} else 1
                )
            if arguments.command == "scheduled-matcher":
                document = scheduled_campaign(
                    arguments.project_root, arguments.matcher_campaign
                )
                print(json.dumps(document, indent=2, sort_keys=True))
                return (
                    0
                    if document["state"]
                    not in {"canary-failed", "incomplete-or-failed"}
                    else 1
                )
            return worker_cases(
                arguments.project_root,
                arguments.cases.split(","),
                arguments.mode,
                arguments.matcher_campaign,
            )
        if arguments.command == "scheduled-hashes":
            document = scheduled_hash_analysis(
                arguments.project_root,
                schedule_path=arguments.schedule,
            )
            print(json.dumps(document, indent=2, sort_keys=True))
            return 0
        if arguments.command == "_worker":
            positions = [
                int(value) for value in arguments.positions.split(",") if value
            ]
            return _worker(
                arguments.project_root,
                arguments.runtime,
                arguments.run_id,
                positions,
                arguments.mode,
            )

        if arguments.command == "status":
            document = compile_machine_validation(
                arguments.project_root, arguments.authority
            )
            document["run"] = runtime_status(arguments.project_root)
            print(json.dumps(document, indent=2, sort_keys=True))
            return 0
        if arguments.command == "reconcile":
            document = reconcile_machine_validation(
                arguments.project_root, arguments.authority
            )
            print(json.dumps(document, indent=2, sort_keys=True))
            return 0

        document = compile_validation_batch(arguments.project_root, arguments.authority)
        if arguments.write:
            write_validation_batch(document, arguments.project_root)
            check = {
                "state": "written-scheduled-claim-blocked",
                "mismatches": [],
            }
        elif arguments.check:
            check = check_validation_batch(document, arguments.project_root)
        else:
            check = {"state": "preview", "mismatches": []}
        document.pop("rendered_manifest")
        document.pop("rendered_schedule")
        document["check"] = check
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0 if check["state"] != "drifted" else 1
    except (OSError, ValueError, PipelineError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def _ecological_validation_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="fidb-poc ecological-validation",
        description="Import hostile binaries without execution and check a compatible lane corpus.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    status = commands.add_parser("status")
    imported = commands.add_parser("import")
    run = commands.add_parser("run")
    for child in (status, imported, run):
        child.add_argument("--project-root", type=Path, default=Path.cwd())
        child.add_argument(
            "--authority",
            type=Path,
            default=Path("validation/ecological-validation.toml"),
        )
    imported.add_argument("path", type=Path)
    imported.add_argument("--label", required=True)
    imported.add_argument(
        "--platform-hint",
        choices=("auto", "linux", "android", "windows", "macos", "ios"),
        default="auto",
    )
    imported.add_argument("--expected-present", action="append", default=[])
    imported.add_argument("--expected-absent", action="append", default=[])
    imported.add_argument("--truth-complete", action="store_true")
    run.add_argument("--case", required=True)
    arguments = parser.parse_args(argv)
    try:
        from .ecological_validation import (
            compile_ecological_validation,
            import_ecological_binary,
            run_ecological_case,
        )

        if arguments.command == "status":
            document = compile_ecological_validation(
                arguments.project_root, arguments.authority
            )
        elif arguments.command == "import":
            source = arguments.path.expanduser().resolve()
            with source.open("rb") as stream:
                document = import_ecological_binary(
                    arguments.project_root,
                    stream,
                    source.stat().st_size,
                    {
                        "filename": source.name,
                        "label": arguments.label,
                        "platform_hint": arguments.platform_hint,
                        "expected_present": arguments.expected_present,
                        "expected_absent": arguments.expected_absent,
                        "truth_complete": arguments.truth_complete,
                    },
                    arguments.authority,
                )
        else:
            document = run_ecological_case(
                arguments.project_root, arguments.case, arguments.authority
            )
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, sqlite3.Error, PipelineError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def _noisy_hashes_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="fidb-poc noisy-hashes",
        description="Inspect or adjudicate recurring validation collisions.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    status = commands.add_parser("status")
    decide = commands.add_parser("decide")
    for child in (status, decide):
        child.add_argument("--project-root", type=Path, default=Path.cwd())
        child.add_argument(
            "--authority",
            type=Path,
            default=Path("validation/noisy-hashes.toml"),
        )
    decide.add_argument("signature_id")
    decide.add_argument(
        "state", choices=("observe", "quarantine", "reviewed-shared", "cleared")
    )
    decide.add_argument("--reason", required=True)
    arguments = parser.parse_args(argv)
    try:
        from .noisy_hashes import compile_noisy_hashes, save_noisy_hash_decision

        document = (
            compile_noisy_hashes(arguments.project_root, arguments.authority)
            if arguments.command == "status"
            else save_noisy_hash_decision(
                arguments.project_root,
                arguments.signature_id,
                arguments.state,
                arguments.reason,
                authority=arguments.authority,
            )
        )
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def _hash_discrimination_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="fidb-poc hash-discrimination",
        description="Inspect the fail-closed Hash Discrimination Index authority.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    status = commands.add_parser("status")
    status.add_argument("--project-root", type=Path, default=Path.cwd())
    status.add_argument(
        "--authority",
        type=Path,
        default=Path("validation/hash-discrimination.toml"),
    )
    arguments = parser.parse_args(argv)
    try:
        from .hash_discrimination import compile_hash_discrimination

        document = compile_hash_discrimination(
            arguments.project_root, arguments.authority
        )
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def _selected_performance(
    arguments: argparse.Namespace,
    *,
    default_heap_mib: int | None,
    require_manual_workers: bool,
) -> dict[str, object]:
    """Resolve either one named profile or the existing explicit CLI controls."""

    explicit_names = (
        "workers",
        "ghidra_heap_mib",
        "ghidra_core_limit",
        "build_jobs_per_cell",
    )
    explicit = [name for name in explicit_names if hasattr(arguments, name)]
    profile_id = getattr(arguments, "performance_profile", None)
    if profile_id or (not explicit and not require_manual_workers):
        if explicit:
            flags = ", ".join(name.replace("_", "-") for name in explicit)
            raise ValueError(
                f"--performance-profile cannot be combined with explicit {flags}"
            )
        from .performance_profiles import load_performance_profiles

        catalog = load_performance_profiles(arguments.project_root)
        profile = catalog.select(profile_id)
        settings = profile.settings
        resolution = None
        if settings.worker_mode == "automatic":
            from .host_capacity import (
                detect_host_capacity,
                resolve_automatic_performance,
            )

            automatic = resolve_automatic_performance(
                detect_host_capacity(), catalog.automatic_policy
            )
            settings = automatic.settings
            resolution = automatic.document()
        return {
            "workers": settings.workers,
            "heap_mib": settings.ghidra_heap_mib,
            "core_limit": settings.ghidra_core_limit,
            "build_jobs_per_cell": settings.build_jobs_per_cell,
            "performance_profile_id": profile.id,
            "performance_resolution": resolution,
        }
    workers = getattr(arguments, "workers", None)
    if require_manual_workers and workers is None:
        raise ValueError("benchmark-width requires --workers or --performance-profile")
    return {
        "workers": workers,
        "heap_mib": getattr(arguments, "ghidra_heap_mib", default_heap_mib),
        "core_limit": getattr(arguments, "ghidra_core_limit", None),
        "build_jobs_per_cell": getattr(arguments, "build_jobs_per_cell", 4),
        "performance_profile_id": "manual" if explicit else "auto",
        "performance_resolution": None,
    }


def _resolve_plan_main(argv: list[str]) -> int:
    result = argparse.ArgumentParser(
        prog="fidb-poc resolve-plan",
        description="Resolve a TOML plan request without building or downloading.",
    )
    result.add_argument("plan", type=Path)
    result.add_argument("--project-root", type=Path, default=Path.cwd())
    result.add_argument("--output", type=Path)
    arguments = result.parse_args(argv)
    try:
        document = resolve_plan(arguments.plan, arguments.project_root)
        if arguments.output:
            write_resolved_plan(document, arguments.output)
            print(f"Resolved plan: {arguments.output}")
        else:
            print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def _compile_width_main(argv: list[str]) -> int:
    result = argparse.ArgumentParser(
        prog="fidb-poc compile-width",
        description="Compile declared C width into applicable and feasible cells.",
    )
    result.add_argument("--project-root", type=Path, default=Path.cwd())
    result.add_argument("--width", default="c-width-v1")
    result.add_argument("--output", type=Path)
    arguments = result.parse_args(argv)
    try:
        from .c_width import compile_c_width

        document = compile_c_width(arguments.project_root, arguments.width)
        payload = json.dumps(document, indent=2, sort_keys=True) + "\n"
        if arguments.output:
            arguments.output.parent.mkdir(parents=True, exist_ok=True)
            arguments.output.write_text(payload, encoding="utf-8")
            print(f"Compiled width: {arguments.output}")
        else:
            print(payload, end="")
        return 0
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def _compile_width_batch_main(argv: list[str]) -> int:
    result = argparse.ArgumentParser(
        prog="fidb-poc compile-width-batch",
        description="Validate and preview one disarmed exact-width batch.",
    )
    result.add_argument("batch")
    result.add_argument("--project-root", type=Path, default=Path.cwd())
    arguments = result.parse_args(argv)
    try:
        from .authority_catalog import authority_catalog

        document = authority_catalog(arguments.project_root)
        matches = [
            row for row in document["width_batches"] if row["id"] == arguments.batch
        ]
        if len(matches) != 1:
            raise ValueError(f"unknown reviewed width batch: {arguments.batch}")
        print(json.dumps(matches[0], indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def _campaign_programme_main(argv: list[str]) -> int:
    result = argparse.ArgumentParser(
        prog="fidb-poc campaign-programme",
        description="Validate and inspect a disarmed research-to-build programme.",
    )
    result.add_argument("--project-root", type=Path, default=Path.cwd())
    result.add_argument(
        "--programme",
        type=Path,
        default=Path("campaigns/c80-four-source-n80-v1.toml"),
    )
    arguments = result.parse_args(argv)
    try:
        from .authority_catalog import authority_catalog

        catalog = authority_catalog(arguments.project_root)
        requested = str(arguments.programme)
        matches = [
            row
            for row in catalog["campaign_programmes"]
            if row["authorities"]["programme"] == requested or row["id"] == requested
        ]
        if len(matches) != 1:
            raise ValueError(f"unknown campaign programme: {requested}")
        print(json.dumps(matches[0], indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def _run_width_main(argv: list[str]) -> int:
    result = argparse.ArgumentParser(
        prog="fidb-poc run-width",
        description=(
            "Preview or explicitly execute the applicability-compiled C width."
        ),
    )
    result.add_argument("--project-root", type=Path, default=Path.cwd())
    result.add_argument("--width", default="c-width-v1")
    result.add_argument(
        "--performance-profile",
        help="select one exact policy from performance/profiles.toml",
    )
    result.add_argument(
        "--canary",
        action="store_true",
        help="select only the authority's baseline O2 cells and one replay",
    )
    result.add_argument(
        "--execute",
        action="store_true",
        help="perform downloads, builds and analysis (otherwise preview only)",
    )
    result.add_argument(
        "--workers",
        type=int,
        default=argparse.SUPPRESS,
        help=(
            "bounded parallel cell workers "
            "(default: memory/CPU-aware and capped at 20; explicit maximum: 32)"
        ),
    )
    heap = result.add_mutually_exclusive_group()
    heap.add_argument(
        "--ghidra-heap-mib",
        type=int,
        dest="ghidra_heap_mib",
        default=argparse.SUPPRESS,
        help="maximum heap per embedded Ghidra JVM (default: 4096 MiB)",
    )
    heap.add_argument(
        "--unbounded-ghidra-heap",
        action="store_const",
        const=None,
        dest="ghidra_heap_mib",
        default=argparse.SUPPRESS,
        help="preserve an inherited -Xmx or use Java's ergonomic heap",
    )
    result.add_argument(
        "--ghidra-core-limit",
        type=int,
        default=argparse.SUPPRESS,
        help="optional Ghidra cpu.core.limit per embedded JVM",
    )
    result.add_argument(
        "--build-jobs-per-cell",
        type=int,
        default=argparse.SUPPRESS,
        help="native compiler jobs within each width cell (default: 4)",
    )
    result.add_argument("--verbose", "-v", action="store_true")
    arguments = result.parse_args(argv)
    try:
        from .width_run import (
            compile_width_run_plan,
            execute_width_run,
            width_run_preview,
        )

        performance = _selected_performance(
            arguments,
            default_heap_mib=4096,
            require_manual_workers=False,
        )

        if not arguments.execute:
            plan = compile_width_run_plan(
                arguments.project_root,
                canary=arguments.canary,
                authority_id=arguments.width,
            )
            print(
                json.dumps(
                    width_run_preview(
                        plan,
                        **performance,
                    ),
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        outcome, path = execute_width_run(
            arguments.project_root,
            canary=arguments.canary,
            authority_id=arguments.width,
            progress=print,
            verbose=arguments.verbose,
            **performance,
        )
        print(f"Width result: {path}")
        return 0 if outcome["state"] == "measured-complete" else 1
    except (OSError, ValueError, PipelineError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def _benchmark_width_main(argv: list[str]) -> int:
    result = argparse.ArgumentParser(
        prog="fidb-poc benchmark-width",
        description="Preview or execute a bounded subset of reviewed width cells.",
    )
    result.add_argument("--project-root", type=Path, default=Path.cwd())
    result.add_argument("--width", default="c-width-v1")
    result.add_argument("--label", default="width-pipeline")
    result.add_argument(
        "--performance-profile",
        help="select one exact policy from performance/profiles.toml",
    )
    result.add_argument("--route", action="append", required=True, dest="routes")
    result.add_argument(
        "--treatment", action="append", required=True, dest="treatments"
    )
    result.add_argument("--workers", type=int, default=argparse.SUPPRESS)
    result.add_argument("--ghidra-heap-mib", type=int, default=argparse.SUPPRESS)
    result.add_argument("--ghidra-core-limit", type=int, default=argparse.SUPPRESS)
    result.add_argument("--build-jobs-per-cell", type=int, default=argparse.SUPPRESS)
    result.add_argument(
        "--execute",
        action="store_true",
        help="run the selected cells; preview is otherwise the default",
    )
    result.add_argument("--verbose", "-v", action="store_true")
    arguments = result.parse_args(argv)
    try:
        from .width_benchmark import (
            execute_width_benchmark,
            width_benchmark_preview,
        )

        performance = _selected_performance(
            arguments,
            default_heap_mib=None,
            require_manual_workers=True,
        )

        options = {
            "project_root": arguments.project_root,
            "authority_id": arguments.width,
            "route_ids": arguments.routes,
            "treatment_ids": arguments.treatments,
            **performance,
        }
        if not arguments.execute:
            print(
                json.dumps(width_benchmark_preview(**options), indent=2, sort_keys=True)
            )
            return 0
        outcome, path = execute_width_benchmark(
            **options,
            label=arguments.label,
            progress=print,
            verbose=arguments.verbose,
        )
        print(f"Benchmark result: {path}")
        return 0 if outcome["state"] == "measured-complete" else 1
    except (OSError, ValueError, PipelineError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def _benchmark_backend_main(argv: list[str]) -> int:
    result = argparse.ArgumentParser(
        prog="fidb-poc benchmark-backend",
        description=("Preview or execute an isolated staged-backend qualification."),
    )
    result.add_argument("--project-root", type=Path, default=Path.cwd())
    result.add_argument("--width", default="c-width-v1")
    result.add_argument("--label", default="staged-backend")
    result.add_argument(
        "--backend",
        choices=("python-staged-v1", "rust-staged-v1"),
        required=True,
    )
    result.add_argument("--route", action="append", required=True, dest="routes")
    result.add_argument(
        "--treatment", action="append", required=True, dest="treatments"
    )
    result.add_argument("--build-workers", type=int, required=True)
    result.add_argument("--analysis-workers", type=int, required=True)
    result.add_argument("--build-jobs-per-cell", type=int, default=4)
    result.add_argument("--ghidra-heap-mib", type=int, default=4096)
    result.add_argument("--ghidra-core-limit", type=int)
    result.add_argument("--rust-binary", type=Path)
    result.add_argument("--reference", type=Path)
    result.add_argument("--timeout-seconds", type=int, default=14_400)
    result.add_argument(
        "--execute",
        action="store_true",
        help="run the experiment; preview is otherwise the default",
    )
    result.add_argument("--verbose", "-v", action="store_true")
    arguments = result.parse_args(argv)
    try:
        from .backend_benchmark import (
            backend_benchmark_preview,
            execute_backend_benchmark,
        )

        options = {
            "project_root": arguments.project_root,
            "authority_id": arguments.width,
            "backend": arguments.backend,
            "route_ids": arguments.routes,
            "treatment_ids": arguments.treatments,
            "build_workers": arguments.build_workers,
            "analysis_workers": arguments.analysis_workers,
            "build_jobs_per_cell": arguments.build_jobs_per_cell,
            "heap_mib": arguments.ghidra_heap_mib,
            "core_limit": arguments.ghidra_core_limit,
        }
        if not arguments.execute:
            print(
                json.dumps(
                    backend_benchmark_preview(**options), indent=2, sort_keys=True
                )
            )
            return 0
        outcome, path = execute_backend_benchmark(
            **options,
            label=arguments.label,
            rust_binary=arguments.rust_binary,
            reference_path=arguments.reference,
            timeout_seconds=arguments.timeout_seconds,
            progress=print,
            verbose=arguments.verbose,
        )
        print(f"Backend benchmark result: {path}")
        return 0 if outcome["state"] == "measured-complete" else 1
    except (OSError, ValueError, PipelineError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def _lane_main(argv: list[str]) -> int:
    result = argparse.ArgumentParser(
        prog="fidb-poc lane",
        description="Inspect or compile experimental, reversible lane databases.",
    )
    result.add_argument("--project-root", type=Path, default=Path.cwd())
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("registry", help="print the reviewed lane registry")
    compile_parser = commands.add_parser(
        "compile", help="preview raw width evidence or explicitly build a raw database"
    )
    compile_parser.add_argument("--run", type=Path, required=True)
    compile_parser.add_argument("--lane", required=True)
    compile_parser.add_argument("--replay", type=int, default=1)
    compile_parser.add_argument("--generation")
    compile_parser.add_argument("--output", type=Path)
    compile_parser.add_argument(
        "--execute",
        action="store_true",
        help="write a new raw database; preview is the default",
    )
    inspect_parser = commands.add_parser(
        "inspect", help="validate and summarize an existing raw lane database"
    )
    inspect_parser.add_argument("database", type=Path)
    arguments = result.parse_args(argv)
    root = arguments.project_root.expanduser().resolve()
    try:
        if arguments.command == "registry":
            from .lane_registry import load_lane_registry

            document = load_lane_registry(
                root / "lanes/registry.toml", root / "targets/registry.toml"
            )
        elif arguments.command == "inspect":
            from .lane_database import inspect_lane_database

            document = inspect_lane_database(arguments.database)
        else:
            from .lane_compiler import build_lane_from_plan, compile_lane_plan

            document = compile_lane_plan(
                root, arguments.run, arguments.lane, replay=arguments.replay
            )
            if arguments.execute:
                if not arguments.generation:
                    raise ValueError("--generation is required with --execute")
                output = arguments.output or (
                    root
                    / "var/fidb-lanes"
                    / arguments.lane
                    / f"{arguments.generation}.raw.sqlite3"
                )
                resolved_output = output.expanduser().resolve()
                try:
                    resolved_output.relative_to(root)
                except ValueError as error:
                    raise ValueError(
                        "lane output must remain inside the project root"
                    ) from error
                document = build_lane_from_plan(
                    root, document, resolved_output, arguments.generation
                )
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Resolve library-name requests, fetch pinned sources, and build "
            "one Ghidra FIDB per library/route."
        )
    )
    result.add_argument(
        "--project-root",
        type=Path,
        default=Path.cwd(),
        help="project directory (default: current directory)",
    )
    result.add_argument(
        "--config",
        type=Path,
        help="worker configuration TOML (default: PROJECT/worker.toml)",
    )
    result.add_argument(
        "--library",
        action="append",
        dest="libraries",
        help=(
            "library request to resolve and fetch; repeat for multiple libraries "
            "(default: requested_libraries in worker.toml)"
        ),
    )
    result.add_argument(
        "--request-priority",
        type=int,
        choices=(0, 1, 2),
        default=0,
        help=(
            "priority recorded when a library has no recipe: "
            "0=campaign/analyst, 1=ranked catalogue, 2=discovery (default: 0)"
        ),
    )
    result.add_argument(
        "--doctor",
        action="store_true",
        help="validate configured tools without building",
    )
    result.add_argument(
        "--plan",
        action="store_true",
        help="print the selected build cells without downloading or compiling",
    )
    result.add_argument(
        "--profile",
        default="smoke",
        help="frozen treatment profile from worker.toml (default: smoke)",
    )
    result.add_argument(
        "--route",
        action="append",
        dest="routes",
        help="route id to build; repeat as needed (required when building)",
    )
    result.add_argument(
        "--treatment",
        action="append",
        dest="treatments",
        help="exact treatment id; repeat as needed (overrides --profile)",
    )
    result.add_argument(
        "--fresh",
        action="store_true",
        help="remove only PROJECT/work and PROJECT/output before building",
    )
    result.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="stream compiler/Ghidra command output live instead of only on failure",
    )
    return result


def _validate_queue_token(label: str, value: str) -> None:
    if value != value.strip() or not value:
        raise ValueError(f"{label} must be a non-empty token without outer whitespace")
    if value[0] in "=+-@":
        raise ValueError(f"{label} must not begin with a spreadsheet formula marker")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{label} must not contain control characters")


def _validate_project_checkout(project_root: Path, config_path: Path) -> None:
    if not project_root.is_dir():
        raise PipelineError(f"project root is not a directory: {project_root}")
    if not config_path.is_file() or project_root not in config_path.parents:
        raise PipelineError(
            f"configuration must be a file inside the project root: {config_path}"
        )
    sentinels = (
        project_root / "pyproject.toml",
        project_root / "src/fidb_poc/pipeline.py",
        project_root / "src/fidb_poc/ghidra_fid.py",
        project_root / "recipes",
    )
    missing = [
        str(path.relative_to(project_root))
        for path in sentinels
        if not path.exists()
        or path.resolve() == project_root
        or project_root not in path.resolve().parents
    ]
    if missing:
        raise PipelineError(
            "project root is not an FIDB-POC checkout; missing: " + ", ".join(missing)
        )


def _fresh_targets(project_root: Path) -> tuple[Path, Path]:
    # "artifacts/libs" only -- artifacts/malware and artifacts/fidbs are a
    # different subsystem's data (different trust posture) and must survive
    # a native-build --fresh.
    names = ("work", "artifacts/libs")
    targets = tuple(project_root / name for name in names)
    for target, expected_name in zip(targets, names):
        expected = project_root / expected_name
        if target.name != Path(expected_name).name or target.parent != expected.parent:
            raise PipelineError(f"refusing unsafe --fresh target: {target}")
        if target.is_symlink():
            raise PipelineError(f"refusing symlinked --fresh target: {target}")
        if target.exists() and not target.is_dir():
            raise PipelineError(f"refusing non-directory --fresh target: {target}")
        resolved = target.resolve()
        if resolved != expected:
            raise PipelineError(
                f"refusing --fresh target other than {expected}: {target}"
            )
    if targets[0] in targets[1].parents or targets[1] in targets[0].parents:
        raise PipelineError("refusing overlapping --fresh targets")
    return targets


def main(argv: list[str] | None = None) -> int:
    tokens = sys.argv[1:] if argv is None else argv
    if tokens and tokens[0] == "resolve-plan":
        return _resolve_plan_main(tokens[1:])
    if tokens and tokens[0] == "compile-width":
        return _compile_width_main(tokens[1:])
    if tokens and tokens[0] == "compile-width-batch":
        return _compile_width_batch_main(tokens[1:])
    if tokens and tokens[0] == "campaign-programme":
        return _campaign_programme_main(tokens[1:])
    if tokens and tokens[0] == "campaigns":
        from .campaign_registry import main as campaign_registry_main

        return campaign_registry_main(tokens[1:])
    if tokens and tokens[0] == "qualify-recipes":
        from .recipe_qualification import main as qualification_main

        return qualification_main(tokens[1:])
    if tokens and tokens[0] == "qualification":
        from .qualification_pipeline import main as qualification_pipeline_main

        return qualification_pipeline_main(tokens[1:])
    if tokens and tokens[0] == "performance":
        return _performance_main(tokens[1:])
    if tokens and tokens[0] == "plan-time-blocks":
        return _plan_time_blocks_main(tokens[1:])
    if tokens and tokens[0] == "materialize-batches":
        return _materialize_batches_main(tokens[1:])
    if tokens and tokens[0] == "auto-batches":
        return _auto_batches_main(tokens[1:])
    if tokens and tokens[0] == "machine-validation":
        return _machine_validation_main(tokens[1:])
    if tokens and tokens[0] == "linked-references":
        from .linked_reference_retrofit import main as linked_reference_main

        return linked_reference_main(tokens[1:])
    if tokens and tokens[0] == "ecological-validation":
        return _ecological_validation_main(tokens[1:])
    if tokens and tokens[0] == "noisy-hashes":
        return _noisy_hashes_main(tokens[1:])
    if tokens and tokens[0] == "hash-discrimination":
        return _hash_discrimination_main(tokens[1:])
    if tokens and tokens[0] == "retention":
        from .retention import main as retention_main

        return retention_main(tokens[1:])
    if tokens and tokens[0] == "export":
        from .database_export import main as export_main

        return export_main(tokens[1:])
    if tokens and tokens[0] == "run-width":
        return _run_width_main(tokens[1:])
    if tokens and tokens[0] == "benchmark-width":
        return _benchmark_width_main(tokens[1:])
    if tokens and tokens[0] == "benchmark-backend":
        return _benchmark_backend_main(tokens[1:])
    if tokens and tokens[0] == "lane":
        return _lane_main(tokens[1:])
    if tokens and tokens[0] == "queue":
        from .queue_cli import main as queue_main

        return queue_main(tokens[1:])
    if tokens and tokens[0] == "api":
        from .local_api import main as api_main

        return api_main(tokens[1:])
    if tokens and tokens[0] == "toolchain":
        from .toolchain_cli import main as toolchain_main

        return toolchain_main(tokens[1:])
    if tokens and tokens[0] == "emulator":
        from .emulator_providers import main as emulator_main

        return emulator_main(tokens[1:])
    if tokens and tokens[0] == "source":
        from .source_cli import main as source_main

        return source_main(tokens[1:])
    if tokens and tokens[0] == "worker-api":
        from .remote_api import main as remote_api_main

        return remote_api_main(tokens[1:])
    if tokens and tokens[0] == "remote-worker":
        from .remote_worker import main as remote_worker_main

        return remote_worker_main(tokens[1:])
    if tokens and tokens[0] == "external-worker":
        from .external_workers import main as external_worker_main

        return external_worker_main(tokens[1:])
    if tokens and tokens[0] in _HUNT_SUBCOMMANDS:
        from .hunt_cli import main as hunt_main

        return hunt_main([_HUNT_SUBCOMMANDS[tokens[0]], *tokens[1:]])
    arguments = parser().parse_args(argv)
    if not arguments.doctor and not arguments.plan and not arguments.routes:
        print(
            "error: at least one --route is required when building; "
            "use --plan to inspect the available cells",
            file=sys.stderr,
        )
        return 2
    project_root = arguments.project_root.resolve()
    config_path = (arguments.config or project_root / "worker.toml").resolve()
    try:
        for library in arguments.libraries or ():
            _validate_queue_token("--library", library)
        for route in arguments.routes or ():
            _validate_queue_token("--route", route)
        request_override = tuple(arguments.libraries) if arguments.libraries else None
        configuration = load_configuration(config_path, request_override)
        configuration = select_configuration(
            configuration,
            route_ids=tuple(arguments.routes) if arguments.routes else None,
            treatment_ids=(
                tuple(arguments.treatments) if arguments.treatments else None
            ),
            profile=arguments.profile,
        )
        if arguments.doctor:
            for message in doctor(configuration, project_root):
                print(message)
            return 0
        if arguments.plan:
            for message in plan(configuration):
                print(message)
            return 0
        _validate_project_checkout(project_root, config_path)
        if arguments.fresh:
            for target in _fresh_targets(project_root):
                if target.exists():
                    shutil.rmtree(target)
        execute(configuration, project_root, progress=print, verbose=arguments.verbose)
        return 0
    except RecipesNotFoundError as error:
        queue_path = record_missing_requests(
            project_root / "recipe_requests/pending.csv",
            error.requests,
            priority=arguments.request_priority,
            routes=tuple(arguments.routes or ()),
        )
        print(f"error: {error}", file=sys.stderr)
        print(f"Recipe request list: {queue_path}", file=sys.stderr)
        return 1
    except (OSError, ValueError, PipelineError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
