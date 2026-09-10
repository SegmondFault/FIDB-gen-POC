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
import hashlib
import json
from pathlib import Path
import shutil
import threading
import time
from typing import Callable, ContextManager, Mapping

import pyghidra

from .validation_analysis import (
    FID_BUILD_ANALYSIS_POLICY,
    FID_BUILD_RELOCATABLE_GCC_EXCEPTION_DISABLED_POLICY,
    FID_BUILD_RECOVERY_ANALYSIS_POLICY,
    GHIDRA_DEFAULT_DIAGNOSTIC_POLICY,
    GHIDRA_LSDA_BURST_DIAGNOSTIC_POLICY,
    QUERY_ANALYSIS_POLICY,
    QUERY_ANALYSIS_RECOVERY_POLICY,
)

LSDA_LOGGER_NAME = (
    "ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable."
    "LSDACallSiteTable"
)

_BASE_GHIDRA_ERROR_LOGGER = None
_ACTIVE_GHIDRA_ERROR_LOGGER = None

TimingFactory = Callable[
    [str, str, Mapping[str, object] | None], ContextManager[dict[str, object]]
]


def _safe_project_name(value: str) -> str:
    """Return a collision-resistant Ghidra project name.

    Recipe versions legitimately contain characters such as ``+`` that
    Ghidra rejects in project names.  Preserve its conservative portable
    alphabet and bind every rewrite to the original value so two punctuation
    variants cannot silently share a project.
    """

    normalized = "".join(
        (
            character
            if character.isascii() and (character.isalnum() or character in {"_", "."})
            else "_"
        )
        for character in value
    )
    if not normalized.strip("_."):
        normalized = "FIDB_project"
    if normalized == value:
        return normalized
    suffix = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"{normalized}_{suffix}"


def _safe_project_location(value: Path) -> Path:
    """Return a Ghidra-safe project container without changing its parent.

    Ghidra validates the final directory element independently from the
    project name.  Recipe identifiers may legitimately contain punctuation
    such as ``+``, so bind a rewritten leaf to the original spelling in the
    same way as project names.
    """

    return value.with_name(_safe_project_name(value.name))


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


class _BoundedLsdaErrorLogger:
    """Delegate Ghidra diagnostics while rate-limiting one pathological source."""

    def __init__(
        self,
        delegate,
        *,
        burst: int = 20,
        events_per_minute: float = 20.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.delegate = delegate
        self.capacity = float(burst)
        self.tokens = float(burst)
        self.tokens_per_second = events_per_minute / 60.0
        self.clock = clock
        self.updated_at = clock()
        self.lock = threading.Lock()
        self.passed_lsda = 0
        self.suppressed_lsda = 0

    @staticmethod
    def _source_name(source) -> str:
        try:
            return str(source.getName())
        except (AttributeError, TypeError):
            try:
                return str(source.getClass().getName())
            except (AttributeError, TypeError):
                return ""

    def _allow_lsda(self) -> bool:
        with self.lock:
            now = self.clock()
            elapsed = max(0.0, now - self.updated_at)
            self.tokens = min(
                self.capacity, self.tokens + elapsed * self.tokens_per_second
            )
            self.updated_at = now
            if self.tokens < 1.0:
                self.suppressed_lsda += 1
                return False
            self.tokens -= 1.0
            self.passed_lsda += 1
            return True

    def _forward(self, method: str, source, message, *rest):
        if (
            method == "error"
            and self._source_name(source) == LSDA_LOGGER_NAME
            and not self._allow_lsda()
        ):
            return None
        return getattr(self.delegate, method)(source, message, *rest)

    def trace(self, source, message, *rest):
        return self._forward("trace", source, message, *rest)

    def debug(self, source, message, *rest):
        return self._forward("debug", source, message, *rest)

    def info(self, source, message, *rest):
        return self._forward("info", source, message, *rest)

    def warn(self, source, message, *rest):
        return self._forward("warn", source, message, *rest)

    def error(self, source, message, *rest):
        return self._forward("error", source, message, *rest)


def configure_ghidra_diagnostics(policy: str) -> dict[str, object]:
    """Install or clear the exact-source LSDA limiter in Ghidra's ``Msg`` path.

    Workers reuse their JVM across cells, so every call first removes our
    error-logger proxy.  The default policy therefore restores Ghidra's normal
    logger instead of inheriting a previous cell's performance policy.
    """

    import jpype
    from ghidra.util import ErrorLogger, Msg

    global _ACTIVE_GHIDRA_ERROR_LOGGER, _BASE_GHIDRA_ERROR_LOGGER

    if _BASE_GHIDRA_ERROR_LOGGER is None:
        field = Msg.class_.getDeclaredField("errorLogger")
        field.setAccessible(True)
        _BASE_GHIDRA_ERROR_LOGGER = field.get(None)
    Msg.setErrorLogger(_BASE_GHIDRA_ERROR_LOGGER)
    _ACTIVE_GHIDRA_ERROR_LOGGER = None
    if policy == GHIDRA_DEFAULT_DIAGNOSTIC_POLICY:
        return {"policy": policy, "logger": LSDA_LOGGER_NAME, "filtered": False}
    if policy != GHIDRA_LSDA_BURST_DIAGNOSTIC_POLICY:
        raise ValueError(f"unsupported Ghidra diagnostic policy: {policy}")

    bounded = _BoundedLsdaErrorLogger(_BASE_GHIDRA_ERROR_LOGGER)
    proxy = jpype.JProxy(ErrorLogger, inst=bounded)
    Msg.setErrorLogger(proxy)
    # JPype proxies and their Python delegates must remain strongly referenced
    # for the lifetime of the Java callback registration.
    _ACTIVE_GHIDRA_ERROR_LOGGER = (proxy, bounded)
    return {
        "policy": policy,
        "logger": LSDA_LOGGER_NAME,
        "filtered": True,
        "initial_burst": 20,
        "sustained_events_per_minute": 20,
    }


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


def _configure_fid_build_analysis(program, analysis_policy: str) -> None:
    """Apply the FID-safe baseline and an explicitly selected recovery.

    Linked executable-shaped reference images can encounter the same proven
    SuperH ``ClearFlowAndRepairCmd`` loop as validation queries.  The recovery
    remains a distinct, recorded FID-build policy so query and reference
    construction provenance cannot be conflated.
    """

    _configure_fid_safe_analysis(program)
    if analysis_policy == FID_BUILD_ANALYSIS_POLICY:
        return
    if analysis_policy == FID_BUILD_RECOVERY_ANALYSIS_POLICY:
        _set_registered_analysis_analyzer_enablement(
            program,
            {
                "Call-Fixup Installer": False,
                "Non-Returning Functions - Discovered": False,
            },
        )
        return
    if analysis_policy == FID_BUILD_RELOCATABLE_GCC_EXCEPTION_DISABLED_POLICY:
        _set_registered_analysis_analyzer_enablement(
            program, {"GCC Exception Handlers": False}
        )
        return
    raise ValueError(f"unsupported FID build analysis policy: {analysis_policy}")


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
    analysis_policy: str = FID_BUILD_ANALYSIS_POLICY,
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

    project_dir = _safe_project_location(project_dir)
    project_dir.mkdir(parents=True, exist_ok=True)
    project_name = _safe_project_name(project_name)
    monitor = pyghidra.task_monitor()

    def _prepare_and_analyze(program) -> None:
        _configure_fid_build_analysis(program, analysis_policy)
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
                "analysis_policy": analysis_policy,
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


def _deduplicated_relation_rows(relations, service, hashes_by_address):
    """Mirror Ghidra HashFamily's full-hash relation deduplication."""

    by_full_hash = {}
    for relation in relations:
        address = str(relation.getEntryPoint())
        related_hashes = hashes_by_address.get(address)
        if related_hashes is None:
            related_hashes = service.hashFunction(relation)
            if related_hashes is None:
                continue
            hashes_by_address[address] = related_hashes
        full_hash = int(related_hashes.getFullHash()) & ((1 << 64) - 1)
        by_full_hash[full_hash] = {
            "full_hash": format(full_hash, "016x"),
            "code_unit_size": int(related_hashes.getCodeUnitSize()),
        }
    return [by_full_hash[key] for key in sorted(by_full_hash)]


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

    from ghidra.feature.fid.service import FidProgramSeeker, FidService

    rows: list[dict[str, object]] = []
    with pyghidra.open_project(project_dir, project_name) as project:
        with pyghidra.program_context(project, program_path) as program:
            language = str(program.getLanguageID())
            compiler_spec = str(program.getCompilerSpec().getCompilerSpecID())
            functions = list(program.getFunctionManager().getFunctionsNoStubs(True))
            service = FidService()
            monitor = pyghidra.task_monitor()
            hashes_by_address = {}
            for function in functions:
                monitor.checkCancelled()
                hashes = service.hashFunction(function)
                if hashes is None:
                    continue
                hashes_by_address[str(function.getEntryPoint())] = hashes
            relation_count = 0
            for function in functions:
                monitor.checkCancelled()
                hashes = hashes_by_address.get(str(function.getEntryPoint()))
                if hashes is None:
                    continue

                children = _deduplicated_relation_rows(
                    FidProgramSeeker.getChildren(function, True),
                    service,
                    hashes_by_address,
                )
                parents = _deduplicated_relation_rows(
                    FidProgramSeeker.getParents(function, True),
                    service,
                    hashes_by_address,
                )
                relation_count += len(children) + len(parents)
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
                        "children": children,
                        "parents": parents,
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
    with output.open("rb") as stream:
        output_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
    return {
        "evidence_schema": "fidb-program-signature-evidence/v1",
        "functions_hashed": len(rows),
        "relation_hashes": relation_count,
        "language_id": rows[0]["ghidra_language_id"] if rows else None,
        "compiler_spec_id": rows[0]["ghidra_compiler_spec_id"] if rows else None,
        "artifact_sha256": output_sha256,
        "artifact_bytes": output.stat().st_size,
    }


def _is_missing_project_journal(error: Exception) -> bool:
    """Recognise the narrow transient seen while reopening a saved project."""

    message = str(error)
    return "FileNotFoundException" in message and "~journal.dat" in message


def analyze_and_export_program_signatures(
    target: Path,
    project_parent: Path,
    project_name: str,
    language: str,
    output: Path,
    compiler_spec: str | None = None,
    analysis_policy: str = QUERY_ANALYSIS_POLICY,
    *,
    maximum_journal_retries: int = 1,
) -> tuple[Path, str, dict[str, object], int]:
    """Analyze and export, rebuilding once for Ghidra's missing-journal race.

    The retry is deliberately confined to the observed ``~journal.dat``
    reopen failure. A rebuilt project is derived from the same immutable
    target and analysis authority; every other exception remains fail-closed.
    """

    if maximum_journal_retries < 0:
        raise ValueError("maximum_journal_retries must not be negative")
    journal_retries = 0
    while True:
        if project_parent.exists():
            shutil.rmtree(project_parent)
        project_dir, program_path = analyze_target(
            target,
            project_parent,
            project_name,
            language,
            compiler_spec,
            analysis_policy=analysis_policy,
        )
        try:
            summary = export_program_signatures(
                project_dir, project_name, program_path, output
            )
            return project_dir, program_path, summary, journal_retries
        except Exception as error:
            if (
                journal_retries >= maximum_journal_retries
                or not _is_missing_project_journal(error)
            ):
                raise
            journal_retries += 1


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


def inspect_fid_candidate_source(fidb: Path) -> dict[str, object]:
    """Read compact candidate scalars and raw relation-smash keys from a FIDB.

    Relation keys remain in Ghidra's native FNV-smash representation. The
    portable matcher can therefore test a query parent/child hash without
    expanding a candidate object for every query function.
    """

    from ghidra.feature.fid.db import FidFileManager
    from java.io import File

    manager = FidFileManager.getInstance()
    manager.load()
    fid_file = manager.addUserFidFile(File(str(fidb.resolve())))
    database = fid_file.getFidDB(False)
    candidates: list[dict[str, object]] = []
    relations: dict[str, list[str]] = {"superior": [], "inferior": []}
    try:
        next_hash = -(1 << 63)
        while True:
            boxed_hash = database.findFullHashValueAtOrAfter(next_hash)
            if boxed_hash is None:
                break
            full_hash_signed = int(boxed_hash.longValue())
            for record in database.findFunctionsByFullHash(full_hash_signed):
                library = database.getLibraryForFunction(record)
                candidates.append(
                    {
                        "candidate_id": _portable_candidate_id(record, library),
                        "record_key": _unsigned_hash(record.getID()),
                        "owner": (
                            f"{library.getLibraryFamilyName()}@"
                            f"{library.getLibraryVersion()}"
                        ),
                        "name": str(record.getName()),
                        "full_hash": _unsigned_hash(record.getFullHash()),
                        "specific_hash": _unsigned_hash(record.getSpecificHash()),
                        "specific_hash_additional_size": int(
                            record.getSpecificHashAdditionalSize()
                        ),
                        "code_unit_size": int(record.getCodeUnitSize()),
                        "auto_pass": bool(record.autoPass()),
                        "auto_fail": bool(record.autoFail()),
                        "force_specific": bool(record.isForceSpecific()),
                        "force_relation": bool(record.isForceRelation()),
                    }
                )
            if full_hash_signed == (1 << 63) - 1:
                break
            next_hash = full_hash_signed + 1

        handle = database.getDBHandle()
        for kind, table_name in (
            ("superior", "Superior Table"),
            ("inferior", "Inferior Table"),
        ):
            table = handle.getTable(table_name)
            iterator = table.longKeyIterator()
            while iterator.hasNext():
                relations[kind].append(_unsigned_hash(iterator.next()))
    finally:
        database.close()
        manager.removeUserFile(fid_file)

    candidates.sort(key=lambda row: str(row["candidate_id"]))
    for values in relations.values():
        values.sort()
    with fidb.open("rb") as stream:
        fidb_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
    return {
        "schema_version": "fidb-compact-candidate-source/v1",
        "fidb_sha256": fidb_sha256,
        "candidates": candidates,
        "relations": relations,
    }


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
