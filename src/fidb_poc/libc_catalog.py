"""Select and prepare checksum-pinned libc/toolchain candidates ("cells").

A cell bakes in its own target architecture -- there is no separate Route to
apply, the cell *is* the route. That's a genuinely different shape from the
Library/Route/Treatment matrix (one cell covers one fixed (machine,
endianness, elf_class)), so this stays a parallel, self-contained subsystem
rather than being forced into config.Library. Ported from
compile-stdlib-poc's candidates.py.

Cells come from two places, both TOML, both loaded by their own module:
toolchain_registry.load_toolchains() for mode="archive" (direct prebuilt
libc.a extraction) and recipe_generator.generate_cells() for mode="source"
(VM-isolated cross-compile). This module only operates on already-loaded
cell dicts -- see hunt.py for where the two lists are combined.
"""

from __future__ import annotations

from contextlib import nullcontext
import hashlib
import json
import logging
from pathlib import Path
import shutil
import subprocess
import tarfile
from typing import Callable, ContextManager, Mapping
from urllib.request import Request, urlopen

from .elf import ghidra_language
from .investigate import Investigation
from .source_build import (
    adapter_inputs,
    executor_for,
    run_local_source_build,
    run_qemu_source_build,
)

log = logging.getLogger(__name__)

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


def _skip(
    skipped: Callable[[str, str, Mapping[str, object] | None], None] | None,
    stage: str,
    message: str,
    metrics: Mapping[str, object] | None = None,
) -> None:
    if skipped is not None:
        skipped(stage, message, metrics)


def _skip_archive_build_stages(
    skipped: Callable[[str, str, Mapping[str, object] | None], None] | None,
    *,
    cache_hit: bool,
) -> None:
    metrics = {"candidate_mode": "archive", "cache_hit": cache_hit}
    for stage, message in (
        ("toolchain-acquire", "archive-only candidate has no build toolchain"),
        ("toolchain-extract", "archive-only candidate has no toolchain to extract"),
        ("patch", "archive-only candidate has no source patch phase"),
        ("configure", "archive-only candidate has no configure phase"),
        ("compile", "archive-only candidate requires no compilation"),
    ):
        _skip(skipped, stage, message, metrics)


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _acquisition_stage(input_kind: str) -> str:
    """Keep executor images out of source/toolchain timing distributions."""

    return {
        "source": "source-acquire",
        "toolchain": "toolchain-acquire",
        "vm-iso": "executor-image-acquire",
    }.get(input_kind, "source-acquire")


def select_recipes(
    investigation: Investigation,
    recipes: list[dict[str, object]],
    requested: tuple[str, ...] = (),
) -> list[dict[str, object]]:
    facts = investigation.target
    inferred = [
        package
        for hypothesis in investigation.hypotheses
        if hypothesis.disposition.startswith("build")
        for package in hypothesis.candidate_packages
    ]

    desired = requested or tuple(inferred)

    def wanted(recipe: dict[str, object]) -> bool:
        identity = f'{recipe["family"]}@{recipe["version"]}'
        return recipe["family"] in desired or identity in desired

    compatible = [
        recipe
        for recipe in recipes
        if recipe.get("machine") == facts.machine
        and recipe.get("endianness") == facts.endianness
        and int(recipe.get("elf_class", 0)) == facts.elf_class
        and wanted(recipe)
    ]
    order = {name: index for index, name in enumerate(requested or tuple(inferred))}
    compatible.sort(
        key=lambda recipe: (
            order.get(
                f'{recipe["family"]}@{recipe["version"]}',
                order.get(recipe["family"], 999),
            ),
            int(recipe.get("priority", 100)),
        )
    )
    return compatible


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _verify_input(
    path: Path,
    expected: str,
    timing: TimingFactory | None,
    input_kind: str,
    *,
    fail_mismatch: bool,
) -> bool:
    with _timed(
        timing,
        "input-verification",
        f"verifying pinned {input_kind} archive",
        {
            "input_kind": input_kind,
            "expected_sha256": expected,
            "bytes": path.stat().st_size,
        },
    ) as metrics:
        observed = _file_sha256(path)
        matched = observed == expected
        metrics.update({"observed_sha256": observed, "matched": matched})
        if fail_mismatch and not matched:
            raise ValueError(f"checksum mismatch downloading {path}")
        return matched


def _download_url(
    url: str,
    expected: str,
    cache: Path,
    *,
    timing: TimingFactory | None = None,
    skipped: Callable[[str, str, Mapping[str, object] | None], None] | None = None,
    input_kind: str = "source",
) -> Path:
    archive = cache / expected
    cache.mkdir(parents=True, exist_ok=True)
    acquisition_stage = _acquisition_stage(input_kind)
    if archive.exists():
        if _verify_input(archive, expected, timing, input_kind, fail_mismatch=False):
            log.info("cache hit: %s (sha256=%s) -> %s", url, expected[:12], archive)
            _skip(
                skipped,
                acquisition_stage,
                f"using cached pinned {input_kind} archive",
                {
                    "input_kind": input_kind,
                    "cache_hit": True,
                    "bytes": archive.stat().st_size,
                    "sha256": expected,
                },
            )
            return archive
        archive.unlink()

    log.info("downloading %s -> %s", url, archive)
    temporary = archive.with_suffix(".part")
    request = Request(url, headers={"User-Agent": "fidb-poc/0.1"})
    temporary.unlink(missing_ok=True)
    try:
        with _timed(
            timing,
            acquisition_stage,
            f"acquiring pinned {input_kind} archive",
            {
                "input_kind": input_kind,
                "cache_hit": False,
                "url": url,
                "sha256": expected,
            },
        ) as metrics:
            byte_count = 0
            with urlopen(request) as response, temporary.open("wb") as output:
                while chunk := response.read(1024 * 1024):
                    output.write(chunk)
                    byte_count += len(chunk)
            metrics["bytes"] = byte_count
        _verify_input(temporary, expected, timing, input_kind, fail_mismatch=True)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    temporary.replace(archive)
    log.info("download OK: %s -> %s", url, archive)
    return archive


def _extract_verified(
    archive: Path,
    destination: Path,
    *,
    timing: TimingFactory | None = None,
    stage: str = "source-extract",
    input_kind: str = "source",
) -> str:
    """Extract a tar archive completely, verifying no members were silently dropped.

    tar extraction has been observed to silently skip files when the
    destination directory is being written to concurrently by other work.
    Re-extracting into an empty directory and checking the member count
    catches that instead of shipping a broken toolchain/source tree.
    """
    log.info("extracting %s -> %s", archive, destination)
    with _timed(
        timing,
        stage,
        f"extracting pinned {input_kind} archive",
        {"input_kind": input_kind, "archive_bytes": archive.stat().st_size},
    ) as metrics:
        destination.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive, "r:*") as source:
            names = source.getnames()
            source.extractall(destination, filter="tar")
        top_level = {name.split("/", 1)[0] for name in names if name}
        if len(top_level) != 1:
            raise ValueError(
                f"expected a single top-level directory in {archive}, got {top_level}"
            )
        extracted_count = sum(1 for _ in destination.rglob("*"))
        metrics.update(
            {
                "archive_member_count": len(names),
                "extracted_entry_count": extracted_count,
            }
        )
        if extracted_count < len(names):
            raise ValueError(
                f"incomplete extraction of {archive}: expected {len(names)} entries, got {extracted_count}"
            )
        return next(iter(top_level))


def prepare_recipe(
    recipe: dict[str, object],
    work: Path,
    download_cache: Path,
    *,
    timing: TimingFactory | None = None,
    skipped: Callable[[str, str, Mapping[str, object] | None], None] | None = None,
) -> dict[str, object]:
    """Prepare one recipe's object files, from a prebuilt archive or a from-source build."""
    mode = recipe.get("mode")
    if mode == "source":
        return _prepare_source_recipe(
            recipe, work, download_cache, timing=timing, skipped=skipped
        )
    if mode != "archive":
        raise ValueError(f"unsupported candidate mode: {mode}")
    recipe_digest = _digest(recipe)
    root = work / "prepared" / recipe_digest[:16]
    objects = root / "objects"
    marker = root / "recipe.json"
    label = f'{recipe["family"]} {recipe["version"]} {recipe["variant"]}'
    if marker.exists() and objects.exists() and any(objects.glob("*.o")):
        log.info("already prepared: %s -> %s (skipping archive fetch)", label, objects)
        _skip_archive_build_stages(skipped, cache_hit=True)
        for stage, message in (
            ("source-acquire", "using previously prepared archive candidate"),
            ("input-verification", "prepared archive candidate was already verified"),
            ("source-extract", "prepared archive member was already extracted"),
            ("archive-object-selection", "using previously selected archive objects"),
            ("artifact-validation", "prepared archive objects were already validated"),
        ):
            _skip(
                skipped,
                stage,
                message,
                {
                    "cache_hit": True,
                    "candidate_mode": "archive",
                    "object_count": len(list(objects.glob("*.o"))),
                },
            )
        return _guess(recipe, objects, recipe_digest)

    log.info("preparing archive candidate: %s (url=%s)", label, recipe["url"])
    archive = _download_url(
        str(recipe["url"]),
        str(recipe["sha256"]),
        download_cache,
        timing=timing,
        skipped=skipped,
        input_kind="source",
    )
    _skip_archive_build_stages(skipped, cache_hit=False)
    root.mkdir(parents=True, exist_ok=True)
    library = root / "library.a"
    with _timed(
        timing,
        "source-extract",
        "extracting pinned static-library member",
        {"archive_bytes": archive.stat().st_size},
    ) as extract_metrics:
        with tarfile.open(archive, "r:*") as source:
            member = source.getmember(str(recipe["library_member"]))
            if not member.isfile():
                raise ValueError(f"{member.name} is not a regular archive member")
            extracted = source.extractfile(member)
            if extracted is None:
                raise ValueError(f"cannot extract {member.name}")
            with library.open("wb") as output:
                shutil.copyfileobj(extracted, output)
        extract_metrics.update(
            {"library_member": member.name, "library_bytes": library.stat().st_size}
        )

    members = None
    if "members_file" in recipe:
        members = [
            line.strip()
            for line in Path(str(recipe["members_file"])).read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
    with _timed(
        timing,
        "archive-object-selection",
        "selecting objects from pinned static archive",
        {"requested_member_count": len(members) if members is not None else None},
    ) as object_metrics:
        objects.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["ar", "x", str(library.resolve()), *(members or [])],
            cwd=objects,
            check=True,
        )
        _normalize_object_extensions(objects)
        selected_objects = list(objects.glob("*.o"))
        object_count = len(selected_objects)
        if not object_count:
            log.info("FAILED: no object files extracted for %s", label)
            raise ValueError(
                f"no object files extracted for {recipe['family']} {recipe['version']}"
            )
        object_metrics.update(
            {
                "object_count": object_count,
                "object_bytes": sum(path.stat().st_size for path in selected_objects),
            }
        )
    with _timed(
        timing,
        "artifact-validation",
        "validating archive-only analysis objects",
        {"object_count": object_count},
    ) as validation_metrics:
        if any(path.stat().st_size < 1 for path in selected_objects):
            raise ValueError("archive candidate contains an empty object file")
        validation_metrics["object_bytes"] = sum(
            path.stat().st_size for path in selected_objects
        )
    marker.write_text(
        json.dumps(recipe, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    log.info("prepared OK: %s -> %d object files in %s", label, object_count, objects)
    return _guess(recipe, objects, recipe_digest)


def _normalize_object_extensions(objects: Path) -> None:
    """uClibc's PIC/shared objects come out of `ar x` as .os/.oS, and musl's
    static objects come out as .lo (libtool objects) -- neither is .o.

    Every downstream consumer (this module's own sanity checks,
    ghidra_fid.py's object handling) expects .o, so normalize once here
    rather than teach every glob about extra suffixes.
    """
    for member in objects.iterdir():
        if member.suffix.lower() in (".os", ".lo"):
            member.rename(member.with_suffix(".o"))


def _prepare_source_recipe(
    recipe: dict[str, object],
    work: Path,
    download_cache: Path,
    *,
    timing: TimingFactory | None = None,
    skipped: Callable[[str, str, Mapping[str, object] | None], None] | None = None,
) -> dict[str, object]:
    """Cross-compile a source cell through its explicit executor.

    Config generation (defconfig/oldconfig) needs only a native host
    compiler and runs directly on the host. Only the actual cross-compile,
    which executes the downloaded third-party toolchain, is routed through
    QEMU by default or directly through the invoking Linux environment when
    the caller explicitly selects local.
    """
    executor = executor_for(recipe)
    inputs = adapter_inputs(recipe, "uclibc_defconfig")
    recipe_digest = _digest(recipe)
    root = work / "prepared" / recipe_digest[:16]
    objects = root / "objects"
    marker = root / "recipe.json"
    label = f'{recipe["family"]} {recipe["version"]} {recipe["variant"]}'
    if marker.exists() and objects.exists() and any(objects.glob("*.o")):
        log.info("already compiled: %s -> %s (skipping source build)", label, objects)
        cached_metrics = {
            "cache_hit": True,
            "executor": executor,
            "object_count": len(list(objects.glob("*.o"))),
        }
        for stage, message in (
            ("source-acquire", "prepared source archive is already cached"),
            ("toolchain-acquire", "prepared cross-toolchain is already cached"),
            (
                "executor-image-acquire",
                (
                    "prepared QEMU executor image is already cached"
                    if executor == "qemu"
                    else "local executor requires no VM image"
                ),
            ),
            ("input-verification", "prepared pinned inputs were already verified"),
            ("source-extract", "prepared source tree is already extracted"),
            ("toolchain-extract", "prepared cross-toolchain is already extracted"),
            ("patch", "prepared source patches are already applied"),
            ("configure", "prepared source tree is already configured"),
            ("compile", "using previously prepared source-library objects"),
            ("archive-object-selection", "using previously extracted archive objects"),
        ):
            _skip(skipped, stage, message, cached_metrics)
        return _guess(recipe, objects, recipe_digest)

    log.info(
        "compiling from source: %s (executor=%s source=%s toolchain=%s)",
        label,
        executor,
        recipe["source_url"],
        recipe["toolchain_url"],
    )
    source_archive = _download_url(
        str(recipe["source_url"]),
        str(recipe["source_sha256"]),
        download_cache,
        timing=timing,
        skipped=skipped,
        input_kind="source",
    )
    toolchain_archive = _download_url(
        str(recipe["toolchain_url"]),
        str(recipe["toolchain_sha256"]),
        download_cache,
        timing=timing,
        skipped=skipped,
        input_kind="toolchain",
    )
    iso = None
    if executor == "qemu":
        iso = _download_url(
            str(recipe["vm_iso_url"]),
            str(recipe["vm_iso_sha256"]),
            download_cache,
            timing=timing,
            skipped=skipped,
            input_kind="vm-iso",
        )
    else:
        _skip(
            skipped,
            "executor-image-acquire",
            "local executor requires no VM image",
            {"executor": executor, "cache_hit": False},
        )

    vm_dir = root / "vm"
    if vm_dir.exists():
        shutil.rmtree(vm_dir)
    src_dir_name = _extract_verified(
        source_archive,
        vm_dir,
        timing=timing,
        stage="source-extract",
        input_kind="source",
    )
    toolchain_dir_name = _extract_verified(
        toolchain_archive,
        vm_dir,
        timing=timing,
        stage="toolchain-extract",
        input_kind="toolchain",
    )
    src_root = vm_dir / src_dir_name

    patches = list(recipe.get("patches", []))
    if patches:
        with _timed(
            timing,
            "patch",
            "applying reviewed source patches",
            {"patch_count": len(patches)},
        ):
            for patch in patches:
                log.info("applying patch %s to %s", patch, src_root)
                with Path(str(patch)).open("rb") as patch_file:
                    subprocess.run(
                        ["patch", "-p1"],
                        cwd=src_root,
                        stdin=patch_file,
                        check=True,
                    )
    else:
        _skip(skipped, "patch", "no reviewed patches selected", {"patch_count": 0})

    log.info(
        "configuring: ARCH=%s CROSS=%s in %s",
        recipe["arch"],
        recipe["cross_bin_prefix"],
        src_root,
    )
    with _timed(
        timing,
        "configure",
        "configuring reviewed source-build adapter",
        {"arch": recipe["arch"], "executor": executor},
    ) as configure_metrics:
        subprocess.run(
            [
                "make",
                f"ARCH={recipe['arch']}",
                f"CROSS={recipe['cross_bin_prefix']}",
                "defconfig",
            ],
            cwd=src_root,
            check=True,
        )
        if "kernel_headers_relpath" in recipe:
            headers = (
                f"/root/toolchain/{recipe['kernel_headers_relpath']}"
                if executor == "qemu"
                else str(
                    (
                        vm_dir
                        / toolchain_dir_name
                        / str(recipe["kernel_headers_relpath"])
                    ).resolve()
                )
            )
            subprocess.run(
                [
                    "sed",
                    "-i",
                    f's#^KERNEL_HEADERS=.*#KERNEL_HEADERS="{headers}"#',
                    str(src_root / ".config"),
                ],
                check=True,
            )
            configure_metrics["kernel_headers_configured"] = True
        subprocess.run(
            [
                "make",
                f"ARCH={recipe['arch']}",
                f"CROSS={recipe['cross_bin_prefix']}",
                "oldconfig",
            ],
            cwd=src_root,
            check=True,
            stdin=subprocess.DEVNULL,
        )

    out_dir = vm_dir / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    log.info(
        "cross-compiling %s via %s: src=%s toolchain=%s library=%s",
        label,
        executor,
        src_dir_name,
        toolchain_dir_name,
        recipe["library_path"],
    )
    with _timed(
        timing,
        "compile",
        "executing reviewed cross-build adapter",
        {
            "executor": executor,
            "adapter": inputs.build_adapter,
            "arch": inputs.arch,
            "jobs": inputs.jobs,
            "output_relpath": inputs.output_relpath,
        },
    ) as compile_metrics:
        if executor == "qemu":
            assert iso is not None
            run_qemu_source_build(
                inputs, vm_dir, iso, toolchain_dir_name, src_dir_name=src_dir_name
            )
        else:
            run_local_source_build(
                inputs, src_root, vm_dir / toolchain_dir_name, out_dir
            )
            command_log = out_dir / "reviewed-build-command.log"
            if command_log.is_file():
                compile_metrics.update(
                    {
                        "command_log_relpath_from_source_work": str(
                            command_log.relative_to(work)
                        ),
                        "command_log_bytes": command_log.stat().st_size,
                    }
                )
        built_library = out_dir / Path(str(recipe["library_path"])).name
        if built_library.exists():
            compile_metrics["output_bytes"] = built_library.stat().st_size

    built_library = out_dir / Path(str(recipe["library_path"])).name
    with _timed(
        timing,
        "artifact-validation",
        "validating reviewed build output",
        {"artifact": built_library.name},
    ) as validation_metrics:
        if not built_library.is_file() or built_library.stat().st_size < 1:
            log.info(
                "FAILED: source build for %s did not produce %s",
                label,
                built_library.name,
            )
            raise ValueError(
                f"source build for {recipe['family']} {recipe['version']} did not produce {built_library.name}"
            )
        validation_metrics["bytes"] = built_library.stat().st_size
    log.info("compile OK: %s -> %s", label, built_library)
    with _timed(
        timing,
        "archive-object-selection",
        "extracting analysis objects from static archive",
        {"archive_bytes": built_library.stat().st_size},
    ) as object_metrics:
        objects.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["ar", "x", str(built_library.resolve())], cwd=objects, check=True
        )
        _normalize_object_extensions(objects)
        selected_objects = list(objects.glob("*.o"))
        object_count = len(selected_objects)
        if not object_count:
            log.info("FAILED: no object files extracted for %s", label)
            raise ValueError(
                f"no object files extracted for {recipe['family']} {recipe['version']}"
            )
        object_metrics.update(
            {
                "object_count": object_count,
                "object_bytes": sum(path.stat().st_size for path in selected_objects),
            }
        )
    marker.write_text(
        json.dumps(recipe, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    log.info("prepared OK: %s -> %d object files in %s", label, object_count, objects)
    return _guess(recipe, objects, recipe_digest)


def _guess(
    recipe: dict[str, object], objects: Path, recipe_digest: str
) -> dict[str, object]:
    source_url = (
        recipe["source_url"] if recipe.get("mode") == "source" else recipe["url"]
    )
    source_sha256 = (
        recipe["source_sha256"] if recipe.get("mode") == "source" else recipe["sha256"]
    )
    language = ghidra_language(
        str(recipe["machine"]), str(recipe["endianness"]), int(recipe["elf_class"])
    )
    if language is None:
        raise ValueError(
            f"no Ghidra language mapping for {recipe['machine']} "
            f"({recipe['endianness']}, {recipe['elf_class']}-bit)"
        )
    return {
        "family": recipe["family"],
        "version": str(recipe["version"]),
        "variant": recipe["variant"],
        "language": language,
        "objects": str(objects),
        "pattern": str(recipe.get("pattern", ".*")),
        "limit": int(recipe["limit"]) if "limit" in recipe else None,
        "recipe_digest": recipe_digest,
        "source_url": source_url,
        "source_sha256": source_sha256,
        **(
            {"executor": executor_for(recipe)} if recipe.get("mode") == "source" else {}
        ),
    }
