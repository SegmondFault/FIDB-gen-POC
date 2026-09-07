"""In-process PyGhidra FID database construction.

Runs the JVM inside this Python process via the ``pyghidra`` package instead
of shelling out to Ghidra's ``analyzeHeadless``/``pyghidraRun`` launchers.
That launcher round-trip is what previously hung indefinitely: its version
check silently failed on a `pip`-less venv and fell into a blocking
``input()`` prompt with no terminal attached. The in-process API never spawns
that launcher, so the same failure mode cannot occur.
"""

from __future__ import annotations

from contextlib import nullcontext
import json
from pathlib import Path
from typing import Callable, ContextManager, Mapping

import pyghidra

from .validation_analysis import (
    QUERY_ANALYSIS_POLICY,
    QUERY_ANALYSIS_RECOVERY_POLICY,
)

TimingFactory = Callable[
    [str, str, Mapping[str, object] | None], ContextManager[dict[str, object]]
]


def _timed(
    timing: TimingFactory | None,
    stage: str,
    message: str,
    metrics: Mapping[str, object] | None = None,
) -> ContextManager[dict[str, object]]:
    if timing is None:
        return nullcontext(dict(metrics or {}))
    return timing(stage, message, metrics)


def ensure_started(install_dir: Path, environment: dict[str, str]) -> bool:
    """Launch the JVM once for this process, with an isolated environment.

    The JVM can only be started once per process, so the deterministic
    HOME/XDG isolation that used to be applied per subprocess call is now
    applied once, before the first library is built.
    """
    if pyghidra.started():
        return False
    import os

    os.environ.update(environment)
    pyghidra.start(install_dir=install_dir.resolve())
    return True


def _configure_fid_safe_analysis(program) -> None:
    """Match ``FunctionIDHeadlessPrescript.java``: FID/LID/demangler analyzers
    must be off while importing objects for FID creation, or they corrupt the
    very names FID is meant to identify; the scalar operand analyzer must be
    on so object-file references above 0x0 are resolved correctly.
    """
    from ghidra.program.model.listing import Program

    options = program.getOptions(Program.ANALYSIS_PROPERTIES)
    for name in (
        "Function ID",
        "Library Identification",
        "Demangler Microsoft",
        "Demangler GNU",
        "Demangler Rust",
        "Demangler Swift",
    ):
        if options.contains(name):
            options.setBoolean(name, False)
    if options.contains("Scalar Operand References"):
        options.setBoolean("Scalar Operand References", True)


def _set_registered_analysis_boolean_option(
    program,
    *,
    analyzer_name: str,
    option_name: str,
    value: bool,
) -> None:
    """Set one analyzer child option after registration, or fail closed.

    Ghidra does not register analyzer-specific child options merely because a
    program has been loaded.  It also requires program options to be mutated
    inside a transaction.  Keeping both requirements here prevents later
    target-analysis policies from depending on call-site ordering or silently
    doing nothing.
    """

    options = pyghidra.analysis_properties(program)
    if not options.contains(analyzer_name):
        raise RuntimeError(f"required Ghidra analyzer is unavailable: {analyzer_name}")
    analyzer_options = options.getOptions(analyzer_name)
    if not analyzer_options.contains(option_name):
        raise RuntimeError(
            f"required Ghidra analyzer option is unavailable: "
            f"{analyzer_name}.{option_name}"
        )
    with pyghidra.transaction(program, "Configure FIDB target analysis policy"):
        analyzer_options.setBoolean(option_name, value)


def _set_registered_analysis_analyzer_enablement(
    program,
    enablement: Mapping[str, bool],
) -> None:
    """Atomically set registered analyzer enablement, or fail closed."""

    options = pyghidra.analysis_properties(program)
    missing = [name for name in enablement if not options.contains(name)]
    if missing:
        raise RuntimeError(
            "required Ghidra analyzers are unavailable: " + ", ".join(missing)
        )
    with pyghidra.transaction(program, "Configure FIDB target analyzer policy"):
        for name, enabled in enablement.items():
            options.setBoolean(name, enabled)


def _configure_target_analysis(program, analysis_policy: str) -> None:
    """Apply a named, evidence-recorded target analysis policy.

    Ghidra 12.1.2 can enter a non-converging ``ClearFlowAndRepairCmd`` loop on
    some SuperH images.  A live thread dump proved the immediate caller was
    ``CallFixupAnalyzer``; ``FindNoReturnFunctionsAnalyzer`` has an independent
    unconditional call into the same repair command.  The recovery policy
    therefore disables both repair-producing analyzers.  Callers select it
    only after a retained timeout, so the fallback is deterministic and
    auditable rather than architecture-wide silent drift.
    """

    if analysis_policy == QUERY_ANALYSIS_POLICY:
        return
    if analysis_policy != QUERY_ANALYSIS_RECOVERY_POLICY:
        raise ValueError(f"unsupported query analysis policy: {analysis_policy}")

    _set_registered_analysis_analyzer_enablement(
        program,
        {
            "Call-Fixup Installer": False,
            "Non-Returning Functions - Discovered": False,
        },
    )


def build_library_fidb(
    *,
    objects: list[Path],
    project_dir: Path,
    project_name: str,
    output: Path,
    library: str,
    version: str,
    variant: str,
    language: str,
    compiler_spec: str,
    timing: TimingFactory | None = None,
) -> dict[str, int]:
    """Import+analyze every object into one fresh Ghidra project, then build
    one FID database from all resulting programs.
    """
    from ghidra.feature.fid.db import FidFileManager
    from ghidra.feature.fid.service import FidService
    from ghidra.program.database import ProgramContentHandler
    from ghidra.program.model.lang import LanguageID
    from java.io import File
    from java.util import ArrayList

    if not objects:
        raise ValueError(f"no objects submitted for {library}")

    project_dir.mkdir(parents=True, exist_ok=True)
    monitor = pyghidra.task_monitor()

    def _prepare_and_analyze(program) -> None:
        _configure_fid_safe_analysis(program)
        pyghidra.analyze(program, monitor)

    with pyghidra.open_project(project_dir, project_name, create=True) as project:
        with _timed(
            timing,
            "ghidra-import-analysis",
            "importing and analyzing objects in Ghidra",
            {
                "library": library,
                "object_count": len(objects),
                "object_bytes": sum(path.stat().st_size for path in objects),
                "language": language,
                "compiler_spec": compiler_spec,
            },
        ) as import_metrics:
            for obj in objects:
                loader = pyghidra.program_loader().project(project).source(str(obj))
                loader = loader.language(language).compiler(compiler_spec)
                with loader.load() as loaded:
                    for item in loaded:
                        item.apply(_prepare_and_analyze)
                    loaded.save(monitor)

            programs = ArrayList()
            pyghidra.walk_project(
                project,
                lambda file: programs.add(file),
                file_filter=lambda file: (
                    file.getContentType() == ProgramContentHandler.PROGRAM_CONTENT_TYPE
                ),
            )
            if programs.isEmpty():
                raise RuntimeError(f"no programs were imported for {library}")
            import_metrics["program_count"] = int(programs.size())

        with _timed(
            timing,
            "fid-population",
            "populating packed Ghidra FID database",
            {"library": library, "program_count": int(programs.size())},
        ) as population_metrics:
            output.parent.mkdir(parents=True, exist_ok=True)
            manager = FidFileManager.getInstance()
            manager.load()
            manager.createNewFidDatabase(File(str(output.resolve())))
            fid_file = manager.addUserFidFile(File(str(output.resolve())))
            database = fid_file.getFidDB(True)
            try:
                result = FidService().createNewLibraryFromPrograms(
                    database,
                    library,
                    version,
                    variant,
                    programs,
                    None,
                    LanguageID(language),
                    None,
                    None,
                    monitor,
                )
                database.saveDatabase(
                    f"FIDB PoC deterministic population: {library}", monitor
                )
                # Explicit int(): these getters return boxed Java Integer/Long
                # objects via JPype, not plain Python int, and the pipeline's
                # provenance validation is strict about the exact type.
                counts = {
                    "programs": int(programs.size()),
                    "attempted": int(result.getTotalAttempted()),
                    "added": int(result.getTotalAdded()),
                    "excluded": int(result.getTotalExcluded()),
                }
                population_metrics.update(counts)
                population_metrics["fidb_bytes"] = output.stat().st_size
                return counts
            finally:
                database.close()
                manager.removeUserFile(fid_file)


def export_fid_signatures(fidb: Path, output: Path, language: str) -> dict[str, int]:
    """Export deterministic function-level matching identities from a FIDB.

    A packed FIDB's byte hash identifies its container, not its matching
    coverage. The composite tuple exported here is the reusable comparison
    unit for compiler/treatment marginal-coverage analysis.
    """

    from ghidra.feature.fid.db import FidFileManager
    from java.io import File

    manager = FidFileManager.getInstance()
    manager.load()
    fid_file = manager.addUserFidFile(File(str(fidb.resolve())))
    database = fid_file.getFidDB(False)
    rows: list[dict[str, object]] = []
    try:
        next_hash = -(1 << 63)
        while True:
            boxed_hash = database.findFullHashValueAtOrAfter(next_hash)
            if boxed_hash is None:
                break
            full_hash_signed = int(boxed_hash.longValue())
            full_hash = format(full_hash_signed & ((1 << 64) - 1), "016x")
            for record in database.findFunctionsByFullHash(full_hash_signed):
                rows.append(
                    {
                        "language": language,
                        "full_hash": full_hash,
                        "specific_hash": format(
                            int(record.getSpecificHash()) & ((1 << 64) - 1),
                            "016x",
                        ),
                        "specific_hash_additional_size": int(
                            record.getSpecificHashAdditionalSize()
                        ),
                        "code_unit_size": int(record.getCodeUnitSize()),
                        "name": str(record.getName()),
                        "domain_path": str(record.getDomainPath()),
                    }
                )
            if full_hash_signed == (1 << 63) - 1:
                break
            next_hash = full_hash_signed + 1
    finally:
        database.close()
        manager.removeUserFile(fid_file)

    rows.sort(
        key=lambda row: (
            row["language"],
            row["full_hash"],
            row["specific_hash"],
            row["specific_hash_additional_size"],
            row["code_unit_size"],
            row["name"],
            row["domain_path"],
        )
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.part")
    temporary.unlink(missing_ok=True)
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            for row in rows:
                stream.write(json.dumps(row, sort_keys=True, separators=(",", ":")))
                stream.write("\n")
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)

    full_hashes = {str(row["full_hash"]) for row in rows}
    signatures = {
        (
            str(row["language"]),
            str(row["full_hash"]),
            str(row["specific_hash"]),
            int(row["specific_hash_additional_size"]),
            int(row["code_unit_size"]),
        )
        for row in rows
    }
    return {
        "records": len(rows),
        "unique_full_hashes": len(full_hashes),
        "unique_signatures": len(signatures),
    }


def compiler_spec_for_language(language: str) -> str:
    """x86/x86-64 only define a "default" spec for 16-bit real mode; ELF
    binaries need the "gcc" spec. Every other processor defines "default" as
    the ELF/gcc-compatible spec, so only x86 is special-cased. Used for
    hunting (targets and catalog recipes), which have no Route to read an
    explicit compiler spec from -- build_library_fidb always takes one
    explicitly instead, since Route already carries the exact spec.
    """
    return "gcc" if language.startswith("x86:") else "default"


def analyze_target(
    target: Path,
    project_parent: Path,
    project_name: str,
    language: str,
    compiler_spec: str | None = None,
    analysis_policy: str = QUERY_ANALYSIS_POLICY,
) -> tuple[Path, str]:
    """Import and analyze an unknown target once, then reuse its project."""
    project_parent.mkdir(parents=True, exist_ok=True)
    program_path = f"/{target.name}"
    monitor = pyghidra.task_monitor()
    with pyghidra.open_project(project_parent, project_name, create=True) as project:
        existing: set[str] = set()
        pyghidra.walk_project(
            project, lambda file: existing.add(str(file.getPathname()))
        )
        if program_path not in existing:
            loader = (
                pyghidra.program_loader().project(project).source(str(target.resolve()))
            )
            loader = loader.language(language).compiler(
                compiler_spec or compiler_spec_for_language(language)
            )
            with loader.load() as loaded:
                for item in loaded:
                    def _analyze(program) -> None:
                        _configure_target_analysis(program, analysis_policy)
                        pyghidra.analyze(program, monitor)

                    item.apply(_analyze)
                loaded.save(monitor)
    return project_parent, program_path


def export_program_signatures(
    project_dir: Path,
    project_name: str,
    program_path: str,
    output: Path,
) -> dict[str, object]:
    """Export exact FID hash tuples from an already analysed target program.

    This is the target-side counterpart to :func:`export_fid_signatures`.
    It deliberately emits observations rather than deciding ownership; the
    ecological validator compares these tuples with the immutable lane corpus
    and keeps that comparison independently inspectable.
    """

    from ghidra.feature.fid.service import FidService

    rows: list[dict[str, object]] = []
    with pyghidra.open_project(project_dir, project_name) as project:
        with pyghidra.program_context(project, program_path) as program:
            language = str(program.getLanguageID())
            compiler_spec = str(program.getCompilerSpec().getCompilerSpecID())
            functions = program.getFunctionManager().getFunctionsNoStubs(True)
            service = FidService()
            monitor = pyghidra.task_monitor()
            for function in functions:
                monitor.checkCancelled()
                hashes = service.hashFunction(function)
                if hashes is None:
                    continue
                rows.append(
                    {
                        "address": str(function.getEntryPoint()),
                        "function_name": str(function.getName()),
                        "ghidra_language_id": language,
                        "ghidra_compiler_spec_id": compiler_spec,
                        "full_hash": format(
                            int(hashes.getFullHash()) & ((1 << 64) - 1), "016x"
                        ),
                        "specific_hash": format(
                            int(hashes.getSpecificHash()) & ((1 << 64) - 1),
                            "016x",
                        ),
                        "specific_hash_additional_size": int(
                            hashes.getSpecificHashAdditionalSize()
                        ),
                        "code_unit_size": int(hashes.getCodeUnitSize()),
                    }
                )

    rows.sort(
        key=lambda row: (
            str(row["address"]),
            str(row["full_hash"]),
            str(row["specific_hash"]),
        )
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.part")
    temporary.unlink(missing_ok=True)
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            for row in rows:
                stream.write(json.dumps(row, sort_keys=True, separators=(",", ":")))
                stream.write("\n")
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "functions_hashed": len(rows),
        "language_id": rows[0]["ghidra_language_id"] if rows else None,
        "compiler_spec_id": rows[0]["ghidra_compiler_spec_id"] if rows else None,
    }


def assess_fidb(
    target_project_dir: Path,
    target_project_name: str,
    target_program: str,
    fidb: Path,
    output: Path,
) -> dict[str, object]:
    """Query an analyzed target against exactly one FID database."""
    from ghidra.feature.fid.db import FidFileManager
    from ghidra.feature.fid.service import FidService
    from java.io import File

    with pyghidra.open_project(target_project_dir, target_project_name) as project:
        with pyghidra.program_context(project, target_program) as program:
            manager = FidFileManager.getInstance()
            manager.load()
            for item in manager.getFidFiles():
                item.setActive(False)
            candidate = manager.addUserFidFile(File(str(fidb.resolve())))
            candidate.setActive(True)
            service = FidService()
            query = manager.openFidQueryService(program.getLanguage(), False)
            matches = []
            matched_functions = 0
            try:
                results = service.processProgram(
                    program,
                    query,
                    service.getDefaultScoreThreshold(),
                    pyghidra.task_monitor(),
                )
                for result in results:
                    matched_functions += 1
                    for match in result.matches:
                        record = match.getFunctionRecord()
                        library = match.getLibraryRecord()
                        matches.append(
                            {
                                "address": str(result.function.getEntryPoint()),
                                "name": str(record.getName()),
                                "score": float(match.getOverallScore()),
                                "full_hash": format(
                                    int(result.hashQuad.getFullHash())
                                    & ((1 << 64) - 1),
                                    "016x",
                                ),
                                "specific_hash": format(
                                    int(result.hashQuad.getSpecificHash())
                                    & ((1 << 64) - 1),
                                    "016x",
                                ),
                                "library": str(library.getLibraryFamilyName()),
                                "version": str(library.getLibraryVersion()),
                                "variant": str(library.getLibraryVariant()),
                            }
                        )
            finally:
                query.close()
                manager.removeUserFile(candidate)

    names_by_address: dict[str, set[str]] = {}
    for match in matches:
        names_by_address.setdefault(str(match["address"]), set()).add(
            str(match["name"])
        )
    unambiguous = [
        match for match in matches if len(names_by_address[str(match["address"])]) == 1
    ]
    report = {
        "matched_functions": matched_functions,
        "match_count": len(matches),
        "unambiguous_match_count": len(unambiguous),
        "unambiguous_matches": unambiguous,
        "matches": matches,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def _unsigned_hash(value: int) -> str:
    return format(int(value) & ((1 << 64) - 1), "016x")


def _portable_candidate_id(record, library) -> str:
    """Return a path-independent identity shared by oracle and portable rows."""

    fields = (
        str(library.getLibraryFamilyName()),
        str(library.getLibraryVersion()),
        str(library.getLibraryVariant()),
        str(record.getDomainPath()),
        str(int(record.getEntryPoint()) & ((1 << 64) - 1)),
        str(record.getName()),
        _unsigned_hash(record.getFullHash()),
        _unsigned_hash(record.getSpecificHash()),
    )
    import hashlib

    return hashlib.sha256("\0".join(fields).encode("utf-8")).hexdigest()


def export_fid_oracle_input(
    project_dir: Path,
    project_name: str,
    program_path: str,
    fidbs: list[Path],
    output: Path,
) -> dict[str, object]:
    """Export native ``FidProgramSeeker`` decisions and their exact score inputs.

    This is a qualification boundary, not a second hash implementation. Ghidra
    supplies the hashes, call-family relations, candidate records and oracle
    decisions. The resulting immutable document can be replayed by both the CPU
    and WGPU portable scorers without a JVM.
    """

    from ghidra.feature.fid.db import FidFileManager
    from ghidra.feature.fid.service import FidProgramSeeker, FidService
    from java.io import File

    if not fidbs:
        raise ValueError("native FID oracle requires at least one database")
    for path in fidbs:
        if not path.is_file():
            raise ValueError(f"native FID oracle database is missing: {path}")

    service = FidService()
    monitor = pyghidra.task_monitor()
    functions_output: list[dict[str, object]] = []
    with pyghidra.open_project(project_dir, project_name) as project:
        with pyghidra.program_context(project, program_path) as program:
            manager = FidFileManager.getInstance()
            manager.load()
            for item in manager.getFidFiles():
                item.setActive(False)
            attached = []
            query = None
            try:
                for path in fidbs:
                    item = manager.addUserFidFile(File(str(path.resolve())))
                    item.setActive(True)
                    attached.append(item)
                query = manager.openFidQueryService(program.getLanguage(), False)
                native_by_address: dict[str, list[dict[str, object]]] = {}
                native_results = service.processProgram(
                    program, query, service.getDefaultScoreThreshold(), monitor
                )
                for result in native_results:
                    matches = []
                    for match in result.matches or []:
                        record = match.getFunctionRecord()
                        library = match.getLibraryRecord()
                        matches.append(
                            {
                                "candidate_id": _portable_candidate_id(record, library),
                                "owner": (
                                    f"{library.getLibraryFamilyName()}@"
                                    f"{library.getLibraryVersion()}"
                                ),
                                "name": str(record.getName()),
                                "score": float(match.getOverallScore()),
                                "primary_score": float(
                                    match.getPrimaryFunctionCodeUnitScore()
                                ),
                                "child_score": float(
                                    match.getChildFunctionCodeUnitScore()
                                ),
                                "parent_score": float(
                                    match.getParentFunctionCodeUnitScore()
                                ),
                                "match_mode": str(match.getPrimaryFunctionMatchMode()),
                            }
                        )
                    native_by_address[str(result.function.getEntryPoint())] = sorted(
                        matches, key=lambda row: str(row["candidate_id"])
                    )

                functions = program.getFunctionManager().getFunctionsNoStubs(True)
                for function in functions:
                    monitor.checkCancelled()
                    hashes = service.hashFunction(function)
                    if hashes is None:
                        continue
                    # HashFamily deduplicates relations by full hash. Mirror
                    # that exactly; summing addresses here over-counts common
                    # callees/callers and was caught by the native oracle.
                    children_by_hash = {}
                    for relation in FidProgramSeeker.getChildren(function, True):
                        related_hash = service.hashFunction(relation)
                        if related_hash is not None:
                            children_by_hash[int(related_hash.getFullHash())] = (
                                related_hash
                            )
                    children = list(children_by_hash.values())
                    parents_by_hash = {}
                    for relation in FidProgramSeeker.getParents(function, True):
                        related_hash = service.hashFunction(relation)
                        if related_hash is not None:
                            parents_by_hash[int(related_hash.getFullHash())] = (
                                related_hash
                            )
                    parents = list(parents_by_hash.values())
                    candidate_rows = []
                    for record in query.findFunctionsByFullHash(hashes.getFullHash()):
                        library = query.getLibraryForFunction(record)
                        child_units = sum(
                            int(item.getCodeUnitSize())
                            for item in children
                            if query.getSuperiorFullRelation(record, item)
                        )
                        parent_units = (
                            sum(
                                int(item.getCodeUnitSize())
                                for item in parents
                                if query.getInferiorFullRelation(item, record)
                            )
                            if len(parents) < 500
                            else 0
                        )
                        candidate_rows.append(
                            {
                                "candidate_id": _portable_candidate_id(record, library),
                                "owner": (
                                    f"{library.getLibraryFamilyName()}@"
                                    f"{library.getLibraryVersion()}"
                                ),
                                "name": str(record.getName()),
                                "full_hash": _unsigned_hash(record.getFullHash()),
                                "specific_hash": _unsigned_hash(
                                    record.getSpecificHash()
                                ),
                                "specific_hash_additional_size": int(
                                    record.getSpecificHashAdditionalSize()
                                ),
                                "code_unit_size": int(record.getCodeUnitSize()),
                                "child_code_units": child_units,
                                "parent_code_units": parent_units,
                                "auto_pass": bool(record.autoPass()),
                                "auto_fail": bool(record.autoFail()),
                                "force_specific": bool(record.isForceSpecific()),
                                "force_relation": bool(record.isForceRelation()),
                            }
                        )
                    address = str(function.getEntryPoint())
                    functions_output.append(
                        {
                            "address": address,
                            "function_name": str(function.getName()),
                            "full_hash": _unsigned_hash(hashes.getFullHash()),
                            "specific_hash": _unsigned_hash(hashes.getSpecificHash()),
                            "specific_hash_additional_size": int(
                                hashes.getSpecificHashAdditionalSize()
                            ),
                            "code_unit_size": int(hashes.getCodeUnitSize()),
                            "candidates": sorted(
                                candidate_rows,
                                key=lambda row: str(row["candidate_id"]),
                            ),
                            "native_matches": native_by_address.get(address, []),
                        }
                    )
            finally:
                if query is not None:
                    query.close()
                for item in attached:
                    manager.removeUserFile(item)

            document = {
                "schema_version": "fidb-portable-fid-input/v1",
                "oracle": "ghidra-fid-program-seeker",
                "language_id": str(program.getLanguageID()),
                "compiler_spec_id": str(program.getCompilerSpec().getCompilerSpecID()),
                "score_threshold": float(service.getDefaultScoreThreshold()),
                "medium_code_unit_limit": int(
                    service.getMediumHashCodeUnitLengthLimit()
                ),
                "functions": sorted(
                    functions_output, key=lambda row: str(row["address"])
                ),
            }

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.part")
    temporary.unlink(missing_ok=True)
    try:
        temporary.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    return document


def export_raw_fidbf(packed: Path, output: Path) -> Path:
    """Convert an attachable packed .fidb into Ghidra's installed raw .fidbf
    format -- the shape Ghidra's own bundled reference libraries ship in
    under Ghidra/Features/FunctionID/data/*.fidbf. build_library_fidb only
    ever produces the packed .fidb form.
    """
    from db import DBHandle
    from ghidra.feature.fid.db import FidFileManager
    from java.io import File

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".part")
    temporary.unlink(missing_ok=True)
    manager = FidFileManager.getInstance()
    manager.load()
    fid_file = manager.addUserFidFile(File(str(packed.resolve())))
    database = fid_file.getFidDB(False)
    try:
        database.saveRawDatabaseFile(
            File(str(temporary.resolve())), pyghidra.task_monitor()
        )
    finally:
        database.close()
        manager.removeUserFile(fid_file)

    handle = DBHandle(File(str(temporary.resolve())))
    handle.close()
    temporary.replace(output)
    return output
